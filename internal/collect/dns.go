package collect

import (
	"encoding/binary"
	"strings"
)

type DNSRecord struct {
	Name string
	IP   string
	Kind string // "a", "aaaa", "ptr"
}

func ParseDNSAnswers(pkt []byte) []DNSRecord {
	if len(pkt) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, n := dnsName(pkt, off)
		if n < 0 {
			return nil
		}
		off = n + 4
		if off > len(pkt) {
			return nil
		}
	}
	var out []DNSRecord
	for i := 0; i < an && off < len(pkt); i++ {
		name, n := dnsName(pkt, off)
		if n < 0 {
			break
		}
		off = n
		if off+10 > len(pkt) {
			break
		}
		typ := binary.BigEndian.Uint16(pkt[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		if off+rdlen > len(pkt) {
			break
		}
		rdata := pkt[off : off+rdlen]
		off += rdlen
		switch typ {
		case 1:
			if rdlen == 4 {
				out = append(out, DNSRecord{Name: name, IP: ip4(rdata), Kind: "a"})
			}
		case 28:
			if rdlen == 16 {
				out = append(out, DNSRecord{Name: name, IP: ip6(rdata), Kind: "aaaa"})
			}
		case 12:
			host, _ := dnsName(pkt, off-rdlen)
			if ip := ptrIP(name); ip != "" && host != "" {
				out = append(out, DNSRecord{Name: host, IP: ip, Kind: "ptr"})
			}
		}
	}
	return out
}

func dnsName(pkt []byte, off int) (string, int) {
	var parts []string
	jumped := false
	end := off
	for hops := 0; hops < 16; hops++ {
		if off >= len(pkt) {
			return "", -1
		}
		l := int(pkt[off])
		if l == 0 {
			if !jumped {
				end = off + 1
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(pkt) {
				return "", -1
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:off+2]) & 0x3fff)
			if !jumped {
				end = off + 2
			}
			off = ptr
			jumped = true
			continue
		}
		off++
		if off+l > len(pkt) {
			return "", -1
		}
		parts = append(parts, string(pkt[off:off+l]))
		off += l
		if !jumped {
			end = off
		}
	}
	return strings.ToLower(strings.Join(parts, ".")), end
}

func ip4(b []byte) string {
	return strings.Join([]string{
		itoa(int(b[0])), itoa(int(b[1])), itoa(int(b[2])), itoa(int(b[3])),
	}, ".")
}

func ip6(b []byte) string {
	a, ok := bytesToIP6(b)
	if !ok {
		return ""
	}
	return a
}

func bytesToIP6(b []byte) (string, bool) {
	if len(b) != 16 {
		return "", false
	}
	var parts []string
	for i := 0; i < 16; i += 2 {
		parts = append(parts, trimHex(int(b[i])<<8|int(b[i+1])))
	}
	return strings.Join(parts, ":"), true
}

func trimHex(n int) string {
	const h = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var s [4]byte
	i := 4
	for n > 0 {
		i--
		s[i] = h[n&15]
		n >>= 4
	}
	return string(s[i:])
}

func ptrIP(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasSuffix(name, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(parts) == 4 {
			return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
		}
	}
	if strings.HasSuffix(name, ".ip6.arpa") {
		hexes := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(hexes) != 32 {
			return ""
		}
		var b [16]byte
		for i := 0; i < 32; i++ {
			h := hexes[31-i]
			if len(h) != 1 {
				return ""
			}
			v := hexVal(h[0])
			if v < 0 {
				return ""
			}
			if i%2 == 0 {
				b[i/2] = byte(v) << 4
			} else {
				b[i/2] |= byte(v)
			}
		}
		a, ok := bytesToIP6(b[:])
		if !ok {
			return ""
		}
		return a
	}
	return ""
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	default:
		return -1
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [3]byte
	i := 3
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
