//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

func ListenDNS(stop <-chan struct{}, fn func(DNSRecord)) error {
	inner := make(chan struct{})
	var once sync.Once
	stopAll := func() { once.Do(func() { close(inner) }) }
	defer stopAll()
	go func() {
		select {
		case <-stop:
			stopAll()
		case <-inner:
		}
	}()
	errc := make(chan error, 3)
	go func() { errc <- listenUDPDNS(unix.AF_INET, inner, fn) }()
	go func() { errc <- listenUDPDNS(unix.AF_INET6, inner, fn) }()
	go func() { errc <- listenPacketDNS(inner, fn) }()
	var first error
	for i := 0; i < 3; i++ {
		if err := <-errc; err != nil && first == nil {
			first = err
			stopAll()
		}
	}
	select {
	case <-stop:
		return nil
	default:
		return first
	}
}

func listenUDPDNS(family int, stop <-chan struct{}, fn func(DNSRecord)) error {
	proto := unix.IPPROTO_UDP
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return fmt.Errorf("dns raw: %w", err)
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, err := unix.Read(fd, buf)
		if netRetry(err) {
			continue
		}
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		emitDNS(buf[:n], family == unix.AF_INET6, fn)
	}
}

func listenPacketDNS(stop <-chan struct{}, fn func(DNSRecord)) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("dns packet: %w", err)
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if netRetry(err) {
			continue
		}
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		if n < 1 {
			continue
		}
		switch buf[0] >> 4 {
		case 4:
			emitDNS(buf[:n], false, fn)
		case 6:
			emitDNS(buf[:n], true, fn)
		}
	}
}

func emitDNS(pkt []byte, v6 bool, fn func(DNSRecord)) {
	var payload []byte
	if v6 {
		if len(pkt) < 40 {
			return
		}
		next := int(pkt[6])
		off := 40
		if next == unix.IPPROTO_UDP && len(pkt) >= off+8 {
			if dnsPort(pkt[off : off+8]) {
				payload = pkt[off+8:]
			}
		} else if next == unix.IPPROTO_TCP && len(pkt) >= off+20 {
			payload = tcpDNS(pkt[off:])
		}
	} else {
		if len(pkt) < 20 {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return
		}
		proto := int(pkt[9])
		rest := pkt[ihl:]
		if proto == unix.IPPROTO_UDP && len(rest) >= 8 {
			if dnsPort(rest[:8]) {
				payload = rest[8:]
			}
		} else if proto == unix.IPPROTO_TCP && len(rest) >= 20 {
			payload = tcpDNS(rest)
		}
	}
	for _, r := range ParseDNSAnswers(payload) {
		if r.Name != "" && r.IP != "" {
			fn(r)
		}
	}
}

func dnsPort(udp []byte) bool {
	s := int(binary.BigEndian.Uint16(udp[0:2]))
	d := int(binary.BigEndian.Uint16(udp[2:4]))
	return s == 53 || d == 53
}

func tcpDNS(seg []byte) []byte {
	if len(seg) < 20 {
		return nil
	}
	doff := int(seg[12]>>4) * 4
	if doff < 20 || len(seg) < doff+2 {
		return nil
	}
	sport := int(binary.BigEndian.Uint16(seg[0:2]))
	dport := int(binary.BigEndian.Uint16(seg[2:4]))
	if sport != 53 && dport != 53 {
		return nil
	}
	body := seg[doff:]
	if len(body) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	if n <= 0 || len(body) < 2+n {
		if len(body) > 12 {
			return body
		}
		return nil
	}
	return body[2 : 2+n]
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
