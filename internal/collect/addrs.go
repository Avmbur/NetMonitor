package collect

import (
	"net"
	"net/netip"
	"strings"
)

func LocalAddrs() []netip.Addr {
	v := LocalView(nil)
	return v.Local
}

type NetView struct {
	AddrIface  map[string]string
	Local      []netip.Addr
	Overlay    []netip.Prefix
	DockerNets []netip.Prefix
}

func LocalView(skip map[string]bool) NetView {
	v := NetView{AddrIface: map[string]string{}}
	ifaces, err := net.Interfaces()
	if err != nil {
		return v
	}
	for _, iface := range ifaces {
		name := iface.Name
		if skip[name] {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		overlay := overlayIface(name)
		docker := dockerIface(name)
		for _, ia := range addrs {
			p, ok := ia.(*net.IPNet)
			if !ok || p.IP == nil {
				continue
			}
			a, ok := netip.AddrFromSlice(p.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			ones, bits := p.Mask.Size()
			if ones < 0 {
				continue
			}
			px := netip.PrefixFrom(a, ones)
			if bits == 32 || bits == 128 {
				px = px.Masked()
			}
			if overlay && !a.IsLoopback() {
				v.Overlay = append(v.Overlay, px)
			}
			if docker && !a.IsLoopback() {
				v.DockerNets = append(v.DockerNets, px)
			}
			if a.IsLoopback() {
				continue
			}
			v.Local = append(v.Local, a)
			v.AddrIface[a.String()] = name
		}
	}
	return v
}

func overlayIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"wg", "tailscale", "tun", "zt", "tailscale0"} {
		if n == p || strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
