package netipx

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

func Parse(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

func Canonical(a netip.Addr) string {
	return a.Unmap().String()
}

// UsableNameIP is an address a DNS name may contribute to a rule.
func UsableNameIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

func Bin16(a netip.Addr) []byte {
	a = a.Unmap()
	b := make([]byte, 16)
	if a.Is4() {
		copy(b[10:12], []byte{0xff, 0xff})
		v4 := a.As4()
		copy(b[12:], v4[:])
		return b
	}
	v16 := a.As16()
	copy(b, v16[:])
	return b
}

func Scope(remote netip.Addr, lan, overlay, own []netip.Prefix) string {
	if remote.IsLoopback() {
		return "lan"
	}
	for _, p := range own {
		if p.Contains(remote) {
			return "own"
		}
	}
	for _, p := range overlay {
		if p.Contains(remote) {
			return "overlay"
		}
	}
	for _, p := range lan {
		if p.Contains(remote) {
			return "lan"
		}
	}
	if remote.IsPrivate() || remote.IsLinkLocalUnicast() || isULA(remote) {
		return "lan"
	}
	return "internet"
}

func isULA(a netip.Addr) bool {
	if !a.Is6() {
		return false
	}
	b := a.As16()
	return b[0]&0xfe == 0xfc
}

func PrefixBinRange(p netip.Prefix) (lo, hi []byte) {
	p = p.Masked()
	addr := p.Addr()
	bits := p.Bits()
	loA, hiA := prefixRange(addr, bits)
	return Bin16(loA), Bin16(hiA)
}

func prefixRange(addr netip.Addr, bits int) (netip.Addr, netip.Addr) {
	if addr.Is4() {
		a4 := addr.As4()
		u := binary.BigEndian.Uint32(a4[:])
		var mask uint32
		if bits == 0 {
			mask = 0
		} else {
			mask = ^uint32(0) << (32 - bits)
		}
		lo := u & mask
		hi := lo | ^mask
		var loB, hiB [4]byte
		binary.BigEndian.PutUint32(loB[:], lo)
		binary.BigEndian.PutUint32(hiB[:], hi)
		return netip.AddrFrom4(loB), netip.AddrFrom4(hiB)
	}
	b := addr.As16()
	var lo, hi [16]byte
	full := bits / 8
	rem := bits % 8
	copy(lo[:], b[:])
	copy(hi[:], b[:])
	if rem > 0 {
		m := byte(^uint8(0) << (8 - rem))
		lo[full] &= m
		hi[full] = lo[full] | ^m
		full++
	}
	for i := full; i < 16; i++ {
		lo[i] = 0
		hi[i] = 0xff
	}
	return netip.AddrFrom16(lo), netip.AddrFrom16(hi)
}

func MustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("prefix %s: %v", s, err))
	}
	return p.Masked()
}

func DefaultLAN() []netip.Prefix {
	return []netip.Prefix{
		MustPrefix("10.0.0.0/8"),
		MustPrefix("172.16.0.0/12"),
		MustPrefix("192.168.0.0/16"),
		MustPrefix("fc00::/7"),
	}
}
