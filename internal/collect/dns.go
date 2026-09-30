package collect

import (
	"encoding/binary"
	"sort"
	"strings"
)

type DNSRecord struct {
	Name string
	IP   string
	Kind string // "a", "aaaa", "ptr"
}

type parsedRR struct {
	name, target, ip, kind string
	section                int
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
	ns := int(binary.BigEndian.Uint16(pkt[8:10]))
	ar := int(binary.BigEndian.Uint16(pkt[10:12]))
	off := 12
	var questions []string
	for i := 0; i < qd; i++ {
		name, n := dnsName(pkt, off)
		if n < 0 {
			return nil
		}
		if name != "" {
			questions = append(questions, name)
		}
		off = n + 4
		if off > len(pkt) {
			return nil
		}
	}
	var recs []parsedRR
	read := func(count, section int) bool {
		for i := 0; i < count && off < len(pkt); i++ {
			name, n := dnsName(pkt, off)
			if n < 0 {
				return false
			}
			off = n
			if off+10 > len(pkt) {
				return false
			}
			typ := binary.BigEndian.Uint16(pkt[off : off+2])
			rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
			rdataAt := off + 10
			off = rdataAt + rdlen
			if rdlen < 0 || off > len(pkt) {
				return false
			}
			recs = append(recs, decodeRR(pkt, name, typ, rdataAt, rdlen, section))
		}
		return true
	}
	if !read(an, 0) {
		return aliasDNS(questions, recs)
	}
	if !read(ns, 1) {
		return aliasDNS(questions, recs)
	}
	read(ar, 2)
	return aliasDNS(questions, recs)
}

func decodeRR(pkt []byte, name string, typ uint16, rdataAt, rdlen, section int) parsedRR {
	switch typ {
	case 1:
		if rdlen == 4 {
			return parsedRR{name: name, ip: ip4(pkt[rdataAt : rdataAt+4]), kind: "a", section: section}
		}
	case 28:
		if rdlen == 16 {
			return parsedRR{name: name, ip: ip6(pkt[rdataAt : rdataAt+16]), kind: "aaaa", section: section}
		}
	case 5:
		target, _ := dnsName(pkt, rdataAt)
		return parsedRR{name: name, target: target, section: section}
	case 12:
		if section != 0 {
			return parsedRR{}
		}
		host, _ := dnsName(pkt, rdataAt)
		if ip := ptrIP(name); ip != "" && host != "" {
			return parsedRR{name: host, ip: ip, kind: "ptr", section: section}
		}
	}
	return parsedRR{}
}

// aliasDNS records each address under the owner and under every name that
// CNAMEs to it, including the queried name. Additional-section glue that is
// not on that chain is ignored.
func aliasDNS(questions []string, recs []parsedRR) []DNSRecord {
	cname := map[string]string{}
	for _, r := range recs {
		if r.section == 1 || r.target == "" || r.kind != "" || r.name == "" {
			continue
		}
		cname[r.name] = r.target
	}
	reaches := func(from, owner string) bool {
		seen := map[string]bool{}
		cur := from
		for hops := 0; hops < 8; hops++ {
			if cur == owner {
				return true
			}
			next, ok := cname[cur]
			if !ok || seen[cur] {
				return false
			}
			seen[cur] = true
			cur = next
		}
		return false
	}
	cares := func(owner string) bool {
		for _, q := range questions {
			if q == owner || reaches(q, owner) {
				return true
			}
		}
		for alias := range cname {
			if alias == owner || reaches(alias, owner) {
				return true
			}
		}
		return false
	}
	aliases := func(owner string) []string {
		seen := map[string]bool{owner: true}
		var from []string
		from = append(from, questions...)
		for alias := range cname {
			from = append(from, alias)
		}
		sort.Strings(from)
		var out []string
		for _, name := range from {
			if name == "" || seen[name] || !reaches(name, owner) {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
		return out
	}
	var out []DNSRecord
	emitted := map[string]bool{}
	add := func(name, ip, kind string) {
		if name == "" || ip == "" || kind == "" {
			return
		}
		key := name + "\x00" + ip + "\x00" + kind
		if emitted[key] {
			return
		}
		emitted[key] = true
		out = append(out, DNSRecord{Name: name, IP: ip, Kind: kind})
	}
	for _, r := range recs {
		if r.ip == "" || r.kind == "" {
			continue
		}
		if r.kind == "ptr" {
			add(r.name, r.ip, r.kind)
			continue
		}
		if r.section == 1 {
			continue
		}
		if r.section == 2 && !cares(r.name) {
			continue
		}
		add(r.name, r.ip, r.kind)
		for _, alias := range aliases(r.name) {
			add(alias, r.ip, r.kind)
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
