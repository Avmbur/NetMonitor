package collect

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

func LocalAddrs() []netip.Addr {
	v := LocalView(nil)
	return v.Local
}

type NetView struct {
	AddrIface    map[string]string
	Local        []netip.Addr
	Overlay      []netip.Prefix
	DockerNets   []netip.Prefix
	BridgeIfaces []string
	BridgeNets   []netip.Prefix
}

func LocalView(skip map[string]bool) NetView {
	v := NetView{AddrIface: map[string]string{}}
	seenBridge := map[string]bool{}
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
			if IsDockerBridge(name) && !a.IsLoopback() {
				if !seenBridge[name] {
					seenBridge[name] = true
					v.BridgeIfaces = append(v.BridgeIfaces, name)
				}
				v.BridgeNets = append(v.BridgeNets, px.Masked())
			}
			if a.IsLoopback() {
				continue
			}
			v.Local = append(v.Local, a)
			v.AddrIface[a.String()] = name
		}
	}
	sort.Strings(v.BridgeIfaces)
	return v
}

// IsDockerBridge reports a bridge Docker itself creates: docker0, or br- and
// exactly twelve hex digits. A host bridge named br-lan is not one of them.
func IsDockerBridge(name string) bool {
	n := strings.ToLower(name)
	if n == "docker0" {
		return true
	}
	if len(n) != 15 || !strings.HasPrefix(n, "br-") {
		return false
	}
	for _, c := range n[3:] {
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
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
