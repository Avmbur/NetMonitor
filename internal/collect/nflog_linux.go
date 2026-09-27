//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"netmonitor/internal/protocol"
	"strings"
	"syscall"
)

const NFLogGroup = 100

func logAttr(t uint16, v []byte) []byte {
	n := 4 + len(v)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], t)
	copy(b[4:], v)
	return b
}
func logConfig(fd int, seq uint32, attrs []byte) error {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint16(b[4:], 4<<8|1)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint16(b[18:], NFLogGroup)
	b = append(b, attrs...)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	if e := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return e
	}
	buf := make([]byte, 8192)
	for {
		n, _, e := unix.Recvfrom(fd, buf, 0)
		if netRetry(e) {
			continue
		}
		if e != nil {
			return e
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return e
		}
		for _, m := range msgs {
			if m.Header.Seq == seq && m.Header.Type == unix.NLMSG_ERROR && len(m.Data) >= 4 {
				n := int32(binary.NativeEndian.Uint32(m.Data))
				if n != 0 {
					return syscall.Errno(-n)
				}
				return nil
			}
		}
	}
}
func ListenNFLog(stop <-chan struct{}, fn func(protocol.FirewallPayload, Entry), gap func(error)) error {
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return e
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	if e = logConfig(fd, 1, logAttr(1, []byte{1})); e != nil {
		return fmt.Errorf("NFLOG bind: %w", e)
	}
	mode := []byte{0, 0, 1, 0, 2, 0}
	attrs := logAttr(2, mode)
	attrs = append(attrs, logAttr(5, []byte{0, 0, 0, 1})...)
	attrs = append(attrs, logAttr(6, []byte{0, 1})...)
	if e = logConfig(fd, 2, attrs); e != nil {
		return fmt.Errorf("NFLOG config: %w", e)
	}
	buf := make([]byte, 1<<20)
	var prev uint32
	haveSeq := false
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, _, flags, _, e := unix.Recvmsg(fd, buf, nil, 0)
		if netRetry(e) {
			continue
		}
		if e != nil {
			return e
		}
		if flags&unix.MSG_TRUNC != 0 {
			gap(fmt.Errorf("NFLOG truncated datagram"))
			continue
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return e
		}
		for _, m := range msgs {
			if m.Header.Type != 4<<8 || len(m.Data) < 4 {
				continue
			}
			var packet []byte
			prefix := ""
			hook := byte(255)
			var input int
			walk(m.Data[4:], func(t uint16, v []byte) {
				switch t & 0x3fff {
				case 1:
					if len(v) >= 3 {
						hook = v[2]
					}
				case 4:
					if len(v) >= 4 {
						input = int(binary.BigEndian.Uint32(v))
					}
				case 9:
					packet = append([]byte(nil), v...)
				case 10:
					prefix = strings.TrimRight(string(v), "\x00")
				case 12:
					if len(v) >= 4 {
						seq := binary.BigEndian.Uint32(v)
						if haveSeq && seq != prev+1 {
							gap(fmt.Errorf("NFLOG sequence gap %d..%d", prev+1, seq-1))
						}
						prev = seq
						haveSeq = true
					}
				}
			})
			entry, ok := PacketEntry(packet)
			if !ok {
				gap(fmt.Errorf("NFLOG unsupported/truncated packet header"))
				continue
			}
			verdict := ""
			switch {
			case strings.HasPrefix(prefix, "nm:drop:"):
				verdict = "drop"
			case strings.HasPrefix(prefix, "nm:reject:"):
				verdict = "reject"
			default:
				continue
			}
			dir, lip, rip, lp, rp := Classify(entry, LocalAddrs())
			if hook == 3 {
				dir = "out"
				lip = entry.OrigSrc.String()
				rip = entry.OrigDst.String()
				lp = entry.OrigSport
				rp = entry.OrigDport
			}
			if hook == 1 {
				dir = "in"
				lip = entry.OrigDst.String()
				rip = entry.OrigSrc.String()
				lp = entry.OrigDport
				rp = entry.OrigSport
			}
			if dir == "unknown" {
				continue
			}
			// A dropped reply of a local service is not an outgoing contact.
			if dir == "out" && lp != nil && Listening(entry.Protocol, *lp) && (rp == nil || !Listening(entry.Protocol, *rp)) {
				dir = "in"
			}
			iface := ""
			if input > 0 {
				if i, e := net.InterfaceByIndex(input); e == nil {
					iface = i.Name
				}
			}
			fn(protocol.FirewallPayload{IPVersion: entry.IPVersion, Protocol: entry.Protocol, Direction: dir, LocalIP: lip, RemoteIP: rip, LocalPort: lp, RemotePort: rp, Verdict: verdict, Chain: fmt.Sprint(hook), RuleTag: prefix, InIface: iface, Hits: 1}, entry)
		}
	}
}
func PacketEntry(b []byte) (Entry, bool) {
	var e Entry
	if len(b) < 20 {
		return e, false
	}
	offset := 0
	proto := byte(0)
	switch b[0] >> 4 {
	case 4:
		offset = int(b[0]&15) * 4
		if offset < 20 || len(b) < offset {
			return e, false
		}
		e.IPVersion = 4
		e.OrigSrc, _ = netip.AddrFromSlice(b[12:16])
		e.OrigDst, _ = netip.AddrFromSlice(b[16:20])
		proto = b[9]
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			e.Protocol = protoName(proto)
			return e, true
		}
	case 6:
		if len(b) < 40 {
			return e, false
		}
		offset = 40
		e.IPVersion = 6
		e.OrigSrc, _ = netip.AddrFromSlice(b[8:24])
		e.OrigDst, _ = netip.AddrFromSlice(b[24:40])
		proto = b[6]
		for count := 0; count < 8; count++ {
			if proto != 0 && proto != 43 && proto != 60 && proto != 44 && proto != 51 {
				break
			}
			if len(b) < offset+8 {
				return e, false
			}
			next := b[offset]
			size := (int(b[offset+1]) + 1) * 8
			if proto == 44 {
				size = 8
				if binary.BigEndian.Uint16(b[offset+2:])&0xfff8 != 0 {
					e.Protocol = protoName(next)
					return e, true
				}
			}
			if proto == 51 {
				size = (int(b[offset+1]) + 2) * 4
			}
			offset += size
			proto = next
		}
	default:
		return e, false
	}
	e.Protocol = protoName(proto)
	e.Unreplied = true
	if len(b) < offset+4 {
		return e, false
	}
	if proto == 6 || proto == 17 {
		sp, dp := int(binary.BigEndian.Uint16(b[offset:])), int(binary.BigEndian.Uint16(b[offset+2:]))
		e.OrigSport = &sp
		e.OrigDport = &dp
	}
	if proto == 1 || proto == 58 {
		typ, code := int(b[offset]), int(b[offset+1])
		e.ICMPType = &typ
		e.ICMPCode = &code
	}
	return e, true
}
