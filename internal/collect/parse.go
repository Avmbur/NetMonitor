package collect

import (
	"encoding/binary"
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
	// TCPFlags is the TCP flag byte. TCPFlagsKnown is false for conntrack dumps.
	TCPFlags      int
	TCPFlagsKnown bool
	// NFLOG carries the packet direction from conntrack, for every protocol.
	CTDirectionKnown bool
	CTReply          bool
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
	return ClassifyNets(e, local, nil)
}

func ClassifyNets(e Entry, local []netip.Addr, docker []netip.Prefix) (dir, localIP, remoteIP string, localPort, remotePort *int) {
	loc := make(map[netip.Addr]struct{}, len(local))
	for _, a := range local {
		loc[a.Unmap()] = struct{}{}
	}
	os, od := e.OrigSrc.Unmap(), e.OrigDst.Unmap()
	_, srcLocal := loc[os]
	_, dstLocal := loc[od]
	srcDocker := prefixContains(os, docker)
	dstDocker := prefixContains(od, docker)
	switch {
	case srcDocker && dstLocal && !srcLocal:
		return "tohost", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case srcLocal && dstDocker && !dstLocal:
		return "fromhost", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case srcDocker && dstDocker:
		return "bridge", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case srcLocal && !dstLocal:
		return "out", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case dstLocal && !srcLocal:
		return "in", netipx.Canonical(od), netipx.Canonical(os), e.OrigDport, e.OrigSport
	case srcDocker && !dstLocal && !dstDocker:
		return "out", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	case dstDocker && !srcLocal && !srcDocker:
		return "in", netipx.Canonical(od), netipx.Canonical(os), e.OrigDport, e.OrigSport
	default:
		return "unknown", netipx.Canonical(os), netipx.Canonical(od), e.OrigSport, e.OrigDport
	}
}

func prefixContains(ip netip.Addr, nets []netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

// TCPReply is a TCP packet that does not open a session. A bare SYN does.
// SYN+ACK and later flags are the reply half of a session we already opened.
func (e Entry) TCPReply() bool {
	if e.Protocol != "tcp" || !e.TCPFlagsKnown {
		return false
	}
	const syn, ack = 0x02, 0x10
	return e.TCPFlags&syn == 0 || e.TCPFlags&ack != 0
}

// ClassifySession is Classify with the listening socket deciding the side of a
// conversation: a reply of a local service leaves through the output path, yet
// it belongs to the session somebody opened towards us.
// HostSide is traffic the firewall lets through between a container and the
// host or another container. It is not an external contact.
func HostSide(dir string) bool {
	return dir == "bridge" || dir == "tohost" || dir == "fromhost"
}

func ClassifySession(e Entry, local []netip.Addr) (dir, localIP, remoteIP string, localPort, remotePort *int) {
	return ClassifySessionNets(e, local, nil)
}

func ClassifySessionNets(e Entry, local []netip.Addr, docker []netip.Prefix) (dir, localIP, remoteIP string, localPort, remotePort *int) {
	dir, lip, rip, lp, rp := ClassifyNets(e, local, docker)
	// Порт контейнера не сравниваем со слушающими портами хоста.
	if ip, err := netip.ParseAddr(lip); err == nil && prefixContains(ip, docker) {
		return dir, lip, rip, lp, rp
	}
	if dir == "out" && lp != nil && Listening(e.Protocol, *lp) && (rp == nil || !Listening(e.Protocol, *rp)) {
		dir = "in"
	}
	return dir, lip, rip, lp, rp
}

// setNFLogCTInfo reads NFULA_CT_INFO (enum ip_conntrack_info, network byte order).
// Values 0..2 describe original packets; 3..4 describe replies. Missing or
// unknown values must not be mistaken for an original packet.
func (e *Entry) setNFLogCTInfo(v []byte) {
	e.CTDirectionKnown, e.CTReply = false, false
	if len(v) != 4 {
		return
	}
	info := binary.BigEndian.Uint32(v)
	if info > 4 {
		return
	}
	e.CTDirectionKnown = true
	e.CTReply = info >= 3
}
