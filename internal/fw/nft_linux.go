//go:build linux

package fw

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"netmonitor/internal/policy"
)

func prepareNft(p Policy) error {
	var rs []policy.Rule
	rs = append(rs, p.Rules...)
	rs = append(rs, p.Groups...)
	for _, r := range rs {
		seen := map[string]bool{}
		paths := []string{r.Match.Cgroup}
		for _, b := range r.Match.Bindings {
			paths = append(paths, b.Cgroup)
		}
		for _, raw := range paths {
			if !policy.DedicatedCgroup(raw) {
				continue
			}
			cg := policy.NormalizeCgroup(raw)
			if seen[cg] {
				continue
			}
			seen[cg] = true
			dir := filepath.Join("/sys/fs/cgroup", filepath.FromSlash(cg))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("cgroup %s: %w", cg, err)
			}
		}
	}
	return nil
}

func listLearnHits() []LearnHit {
	var out []LearnHit
	out = append(out, listLearnSet("learn4o", "out")...)
	out = append(out, listLearnSet("learn4i", "in")...)
	out = append(out, listLearnSet("learn6o", "out")...)
	out = append(out, listLearnSet("learn6i", "in")...)
	return out
}

func listLearnSet(name, dir string) []LearnHit {
	b, err := exec.Command("nft", "-j", "list", "set", "inet", "netmon", name).Output()
	if err != nil {
		return nil
	}
	var root struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &root) != nil {
		return nil
	}
	var out []LearnHit
	for _, n := range root.Nftables {
		if n.Set == nil {
			continue
		}
		for _, raw := range n.Set.Elem {
			ip, proto, port, ok := parseLearnElem(raw)
			if !ok {
				continue
			}
			out = append(out, LearnHit{Dir: dir, Proto: proto, IP: ip, Port: port})
		}
	}
	return out
}

func parseLearnElem(raw json.RawMessage) (netip.Addr, string, int, bool) {
	var wrap struct {
		Elem struct {
			Val struct {
				Concat []any `json:"concat"`
			} `json:"val"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrap) != nil {
		return netip.Addr{}, "", 0, false
	}
	c := wrap.Elem.Val.Concat
	if len(c) < 2 {
		return netip.Addr{}, "", 0, false
	}
	ip, err := netip.ParseAddr(fmt.Sprint(c[0]))
	if err != nil {
		return netip.Addr{}, "", 0, false
	}
	proto := protoFromAny(c[1])
	port := 0
	if len(c) > 2 {
		port = intFromAny(c[2])
	}
	return ip.Unmap(), proto, port, true
}

func protoFromAny(v any) string {
	switch x := v.(type) {
	case string:
		if x == "6" {
			return "tcp"
		}
		if x == "17" {
			return "udp"
		}
		if x == "1" {
			return "icmp"
		}
		return x
	case float64:
		return protoName(int(x))
	default:
		return fmt.Sprint(v)
	}
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func protoName(n int) string {
	switch n {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return strconv.Itoa(n)
	}
}
