//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	nlNetfilter      = 12
	nfSubsysCT       = 1
	ipctMsgCTGet     = 1
	nlaFNested       = 0x8000
	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaStatus        = 3
	ctaTimeout       = 7
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaID            = 12
	ctaZone          = 18
	ctaTupleIP       = 1
	ctaTupleProto    = 2
	ctaIPv4Src       = 1
	ctaIPv4Dst       = 2
	ctaIPv6Src       = 3
	ctaIPv6Dst       = 4
	ctaProtoNum      = 1
	ctaProtoSrcPort  = 2
	ctaProtoDstPort  = 3
	ctaCountersPkts  = 1
	ctaCountersBytes = 2
	ipsSeenReply     = 0x00000002
	ipsAssured       = 0x00000004
)

func DumpNetlink() ([]Entry, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, nlNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, err
	}
	req := nlDumpReq()
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []Entry
	buf := make([]byte, 64*1024)
	for {
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if netRetry(err) {
			continue
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("truncated netlink dump")
		}
		if err != nil {
			return out, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return out, err
		}
		done := false
		for _, m := range msgs {
			if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, fmt.Errorf("interrupted conntrack dump")
			}
			if m.Header.Type == unix.NLMSG_DONE {
				done = true
				break
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				return out, fmt.Errorf("netlink error")
			}
			if e, ok := parseCT(m.Data); ok {
				out = append(out, e)
			} else {
				return nil, fmt.Errorf("incomplete conntrack entry in dump")
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

func nlDumpReq() []byte {
	var nfgen [4]byte
	nfgen[0] = unix.AF_UNSPEC
	nfgen[1] = 0
	hdrLen := unix.NLMSG_HDRLEN + 4
	b := make([]byte, hdrLen)
	binary.LittleEndian.PutUint32(b[0:4], uint32(hdrLen))
	binary.LittleEndian.PutUint16(b[4:6], uint16(nfSubsysCT<<8|ipctMsgCTGet))
	binary.LittleEndian.PutUint16(b[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(b[8:12], 1)
	copy(b[unix.NLMSG_HDRLEN:], nfgen[:])
	return b
}

func parseCT(data []byte) (Entry, bool) {
	if len(data) < 4 {
		return Entry{}, false
	}
	attrs := data[4:]
	var e Entry
	e.Protocol = "unknown"
	walk(attrs, func(typ uint16, v []byte) {
		typ &= 0x3fff
		switch typ {
		case ctaTupleOrig:
			parseTuple(v, &e, false)
		case ctaTupleReply:
			parseTuple(v, &e, true)
		case ctaCountersOrig:
			e.CountersKnown = true
			e.OrigPackets, e.OrigBytes = parseCounters(v)
		case ctaCountersReply:
			e.ReplyPackets, e.ReplyBytes = parseCounters(v)
		case ctaStatus:
			if len(v) >= 4 {
				st := binary.BigEndian.Uint32(v[len(v)-4:])
				e.Unreplied = st&ipsSeenReply == 0
				e.Assured = st&ipsAssured != 0
			}
		case ctaID:
			if len(v) >= 4 {
				n := int64(binary.BigEndian.Uint32(v))
				e.CTID = &n
			}
		case 20:
			walk(v, func(t uint16, b []byte) {
				if t&0x3fff == 1 && len(b) >= 8 {
					e.StartNS = int64(binary.BigEndian.Uint64(b))
				}
			})
		case 4:
			walk(v, func(t uint16, b []byte) {
				if t&0x3fff == 1 {
					walk(b, func(a uint16, c []byte) {
						if a&0x3fff == 1 && len(c) > 0 {
							states := []string{"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN", "SYN_SENT2"}
							if int(c[0]) < len(states) {
								e.State = states[c[0]]
							}
						}
					})
				}
			})
		case ctaZone:
			if len(v) >= 2 {
				e.Zone = int(binary.BigEndian.Uint16(v[len(v)-2:]))
			}
		}
	})
	if !e.OrigSrc.IsValid() || !e.OrigDst.IsValid() {
		return Entry{}, false
	}
	if e.IPVersion == 0 {
		if e.OrigSrc.Is4() {
			e.IPVersion = 4
		} else {
			e.IPVersion = 6
		}
	}

	return e, true
}

func parseTuple(v []byte, e *Entry, reply bool) {
	walk(v, func(typ uint16, val []byte) {
		typ &= 0x3fff
		switch typ {
		case ctaTupleIP:
			walk(val, func(t uint16, ip []byte) {
				t &= 0x3fff
				var a netip.Addr
				switch t {
				case ctaIPv4Src, ctaIPv4Dst:
					if len(ip) >= 4 {
						a, _ = netip.AddrFromSlice(ip[:4])
					}
				case ctaIPv6Src, ctaIPv6Dst:
					if len(ip) >= 16 {
						a, _ = netip.AddrFromSlice(ip[:16])
					}
				}
				if !a.IsValid() {
					return
				}
				a = a.Unmap()
				if !reply {
					if t == ctaIPv4Src || t == ctaIPv6Src {
						e.OrigSrc = a
					} else {
						e.OrigDst = a
					}
				} else {
					if t == ctaIPv4Src || t == ctaIPv6Src {
						e.ReplySrc = a
					} else {
						e.ReplyDst = a
					}
				}
			})
		case ctaTupleProto:
			walk(val, func(t uint16, pv []byte) {
				t &= 0x3fff
				switch t {
				case ctaProtoNum:
					if len(pv) >= 1 {
						e.Protocol = protoName(pv[0])
					}
				case ctaProtoSrcPort:
					if len(pv) >= 2 && !reply {
						p := int(binary.BigEndian.Uint16(pv[:2]))
						e.OrigSport = &p
					}
				case 4, 7:
					if !reply && len(pv) >= 2 {
						n := int(binary.BigEndian.Uint16(pv))
						e.ICMPID = &n
					}
				case 5, 8:
					if !reply && len(pv) > 0 {
						n := int(pv[0])
						e.ICMPType = &n
					}
				case 6, 9:
					if !reply && len(pv) > 0 {
						n := int(pv[0])
						e.ICMPCode = &n
					}
				case ctaProtoDstPort:
					if len(pv) >= 2 && !reply {
						p := int(binary.BigEndian.Uint16(pv[:2]))
						e.OrigDport = &p
					}
				}
			})
		}
	})
}

func parseCounters(v []byte) (pkts, bytes int64) {
	walk(v, func(typ uint16, val []byte) {
		typ &= 0x3fff
		if len(val) < 8 {
			return
		}
		n := int64(binary.BigEndian.Uint64(val[len(val)-8:]))
		switch typ {
		case ctaCountersPkts:
			pkts = n
		case ctaCountersBytes:
			bytes = n
		}
	})
	return
}

func walk(b []byte, fn func(typ uint16, val []byte)) {
	for len(b) >= 4 {
		nlen := int(binary.LittleEndian.Uint16(b[0:2]))
		typ := binary.LittleEndian.Uint16(b[2:4])
		if nlen < 4 || nlen > len(b) {
			return
		}
		fn(typ, b[4:nlen])
		nlen = (nlen + 3) &^ 3
		if nlen > len(b) {
			return
		}
		b = b[nlen:]
	}
}

func Watch(stop <-chan struct{}, fn func(Entry, string)) error {
	return WatchReady(stop, fn, func() {})
}
func WatchReady(stop <-chan struct{}, fn func(Entry, string), ready func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, nlNetfilter)
	if err != nil {
		return fmt.Errorf("watch socket: %w", err)
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 | 2 | 4}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return err
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	ready()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if netRetry(err) {
			continue
		}
		if flags&unix.MSG_TRUNC != 0 {
			return fmt.Errorf("truncated conntrack event")
		}
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Type == unix.NLMSG_DONE || m.Header.Type == unix.NLMSG_ERROR {
				continue
			}
			e, ok := parseCT(m.Data)
			if !ok {
				continue
			}
			kind := "update"
			switch m.Header.Type & 0xff {
			case 0:
				if m.Header.Flags&(unix.NLM_F_CREATE|unix.NLM_F_EXCL) != 0 {
					kind = "new"
				}
			case 2:
				kind = "destroy"
			}
			fn(e, kind)
		}
	}
}

func protoName(p byte) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}
