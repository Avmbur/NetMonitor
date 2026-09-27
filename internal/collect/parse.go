package collect

import (
	"net/netip"
	"strconv"
	"strings"

	"netmonitor/internal/netipx"
)

type Entry struct {
	CTID                       *int64
	StartNS                    int64
	Namespace                  string
	ICMPType, ICMPCode, ICMPID *int
	CountersKnown              bool
	IPVersion                  int
	Protocol                   string
	State                      string
	Zone                       int
	OrigSrc                    netip.Addr
	OrigDst                    netip.Addr
	OrigSport                  *int
	OrigDport                  *int
	ReplySrc                   netip.Addr
	ReplyDst                   netip.Addr
	OrigPackets                int64
	OrigBytes                  int64
	ReplyPackets               int64
	ReplyBytes                 int64
	Unreplied                  bool
	Assured                    bool
}

func (e Entry) TupleKey() string {
	return strings.Join([]string{
		e.Namespace, strconv.Itoa(e.Zone), portStr(e.ICMPType), portStr(e.ICMPCode), portStr(e.ICMPID),
		e.Protocol,
		ipStr(e.OrigSrc), portStr(e.OrigSport),
		ipStr(e.OrigDst), portStr(e.OrigDport),
	}, "/")
}

func ParseLine(line string) (Entry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Entry{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Entry{}, false
	}
	var e Entry
	switch fields[0] {
	case "ipv4":
		e.IPVersion = 4
	case "ipv6":
		e.IPVersion = 6
	default:
		return Entry{}, false
	}
	e.Protocol = strings.ToLower(fields[2])
	reply := false
	for _, f := range fields[3:] {
		switch {
		case f == "[UNREPLIED]":
			e.Unreplied = true
			reply = true
		case f == "[ASSURED]":
			e.Assured = true
		case !strings.Contains(f, "="):
			if isState(f) {
				e.State = f
			}
		default:
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			switch k {
			case "src":
				a, err := netipx.Parse(v)
				if err != nil {
					continue
				}
				if !reply && !e.OrigSrc.IsValid() {
					e.OrigSrc = a
				} else {
					e.ReplySrc = a
					reply = true
				}
			case "dst":
				a, err := netipx.Parse(v)
				if err != nil {
					continue
				}
				if !reply && !e.OrigDst.IsValid() {
					e.OrigDst = a
				} else {
					e.ReplyDst = a
				}
			case "sport":
				p := atoi(v)
				if !reply && e.OrigSport == nil {
					e.OrigSport = &p
				}
			case "dport":
				p := atoi(v)
				if !reply && e.OrigDport == nil {
					e.OrigDport = &p
				}
			case "packets":
				n := atoi64(v)
				if !reply {
					e.OrigPackets = n
				} else {
					e.ReplyPackets = n
				}
			case "bytes":
				n := atoi64(v)
				if !reply {
					e.OrigBytes = n
					e.CountersKnown = true
				} else {
					e.ReplyBytes = n
				}
			case "zone":
				e.Zone = atoi(v)
			}
		}
	}
	if !e.OrigSrc.IsValid() || !e.OrigDst.IsValid() {
		return Entry{}, false
	}
	return e, true
}

func Classify(e Entry, local []netip.Addr) (dir, localIP, remoteIP string, localPort, remotePort *int) {
	loc := make(map[netip.Addr]struct{}, len(local))
	for _, a := range local {
		loc[a.Unmap()] = struct{}{}
	}
	os, od := e.OrigSrc.Unmap(), e.OrigDst.Unmap()
	_, srcLocal := loc[os]
	_, dstLocal := loc[od]
	switch {
	case srcLocal && !dstLocal:
		return "out", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case dstLocal && !srcLocal:
		return "in", netipx.Canonical(od), netipx.Canonical(os), e.OrigDport, e.OrigSport
	default:
		return "unknown", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	}
}

func Skip(e Entry, monitor netip.Addr, monitorPort int) bool {
	if e.OrigSrc.IsLoopback() || e.OrigDst.IsLoopback() {
		return true
	}
	if !monitor.IsValid() || monitorPort <= 0 {
		return false
	}
	m := monitor.Unmap()
	if e.OrigDst.Unmap() == m && e.OrigDport != nil && *e.OrigDport == monitorPort {
		return true
	}
	if e.OrigSrc.Unmap() == m && e.OrigSport != nil && *e.OrigSport == monitorPort {
		return true
	}
	return false
}

func isState(s string) bool {
	if s == "" {
		return false
	}
	return s[0] >= 'A' && s[0] <= 'Z' && !strings.HasPrefix(s, "[")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func ipStr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return netipx.Canonical(a)
}

func portStr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

// ClassifySession is Classify with the listening socket deciding the side of a
// conversation: a reply of a local service leaves through the output path, yet
// it belongs to the session somebody opened towards us.
func ClassifySession(e Entry, local []netip.Addr) (dir, localIP, remoteIP string, localPort, remotePort *int) {
	dir, lip, rip, lp, rp := Classify(e, local)
	if dir == "out" && lp != nil && Listening(e.Protocol, *lp) && (rp == nil || !Listening(e.Protocol, *rp)) {
		dir = "in"
	}
	return dir, lip, rip, lp, rp
}
