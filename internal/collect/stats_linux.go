//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"syscall"
)

func ConntrackFailures() (map[string]uint64, error) {
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return nil, e
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	b := nlDumpReq()
	binary.NativeEndian.PutUint16(b[4:], 1<<8|4)
	if e = unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return nil, e
	}
	out := map[string]uint64{}
	buf := make([]byte, 65536)
	for {
		n, _, e := unix.Recvfrom(fd, buf, 0)
		if e != nil {
			return nil, e
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return nil, e
		}
		for _, m := range msgs {
			if m.Header.Type == unix.NLMSG_DONE {
				return out, nil
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				return nil, fmt.Errorf("conntrack stats netlink error")
			}
			if len(m.Data) < 4 {
				continue
			}
			walk(m.Data[4:], func(t uint16, v []byte) {
				name := map[uint16]string{9: "insert_failed", 10: "drop", 11: "early_drop", 12: "error"}[t&0x3fff]
				if name != "" && len(v) >= 4 {
					out[name] += uint64(binary.BigEndian.Uint32(v))
				}
			})
		}
	}
}
