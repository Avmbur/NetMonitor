package fw

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const activeSet = "nm_active"

// A list:set contains both address families. Switching this ONE list atomically
// changes the IPv4/IPv6 policy; per-family iptables hooks remain fixed.
func (c *Controller) applyIPTables(p Policy) error {
	// Шторм на iptables не собрать; баны важнее, живём по режиму без шторма.
	p.Mode, _ = SplitMode(p.Mode)
	if p.Mode != "" && p.Mode != "allow" {
		return fmt.Errorf("iptables: strict mode %q is unavailable: reliable learning/service restrictions require nftables; existing bans unchanged", p.Mode)
	}
	now := time.Now()
	entries, err := fallbackEntries(p, now)
	if err != nil {
		return err
	}
	for _, cmd := range []string{"iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "ipset"} {
		if _, err := c.execute("", cmd, "--version"); err != nil {
			return err
		}
	}
	if _, err := c.execute("", "ipset", "create", activeSet, "list:set", "size", "8", "-exist"); err != nil {
		return err
	}
	old, err := c.execute("", "ipset", "save", activeSet)
	if err != nil {
		return err
	}
	var oldChildren []string
	for _, line := range strings.Split(string(old), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "add" && f[1] == activeSet && ownedSet(f[2]) {
			oldChildren = append(oldChildren, f[2])
		}
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	stem := "nm_p_" + hex.EncodeToString(token[:])
	temp := stem + "l"
	v4 := stem + "4"
	v6 := stem + "6"
	committed := false
	defer func() {
		// Only destroy names created by this operation, never the active list.
		_, _ = c.execute("", "ipset", "destroy", temp)
		names := []string{v4, v6}
		if committed {
			names = oldChildren
		}
		for _, name := range names {
			_, _ = c.execute("", "ipset", "destroy", name)
		}
	}()
	var script strings.Builder
	fmt.Fprintf(&script, "create %s list:set size 8\ncreate %s hash:net family inet timeout 0 maxelem 262144\ncreate %s hash:net family inet6 timeout 0 maxelem 262144\n", temp, v4, v6)
	for _, e := range entries {
		set := v4
		if e.net.Addr().Is6() {
			set = v6
		}
		seconds := int64(0)
		if e.expiry > 0 {
			seconds = (e.expiry - now.UnixMilli()) / 1000
			if seconds <= 0 {
				continue
			}
			if seconds > 2147483 {
				return fmt.Errorf("iptables: timeout exceeds ipset limit")
			}
		}
		fmt.Fprintf(&script, "add %s %s timeout %d\n", set, e.net, seconds)
	}
	fmt.Fprintf(&script, "add %s %s\nadd %s %s\n", temp, v4, temp, v6)
	if _, err := c.execute(script.String(), "ipset", "restore"); err != nil {
		return err
	}
	// Every fallible preparation precedes the only policy-switching command.
	for _, tool := range []string{"iptables", "ip6tables"} {
		if err := c.installIPTHooks(tool); err != nil {
			return err
		}
	}
	if _, err := c.execute("", "ipset", "swap", activeSet, temp); err != nil {
		return err
	}
	committed = true
	return nil
}
func ownedSet(name string) bool {
	if !strings.HasPrefix(name, "nm_p_") || len(name) != 22 {
		return false
	}
	_, err := hex.DecodeString(name[5:21])
	return err == nil && strings.Contains("46l", name[21:])
}
func (c *Controller) installIPTHooks(tool string) error {
	raw, err := c.execute("", tool+"-save", "-t", "filter")
	if err != nil {
		return err
	}
	var s strings.Builder
	s.WriteString("*filter\n:NM_IN - [0:0]\n:NM_OUT - [0:0]\n-F NM_IN\n-F NM_OUT\n")
	s.WriteString("-A NM_IN -i lo -j RETURN\n-A NM_IN -m set --match-set nm_active src -j NFLOG --nflog-prefix nm:drop:ban:input --nflog-group 100\n-A NM_IN -m set --match-set nm_active src -j DROP\n-A NM_OUT -o lo -j RETURN\n-A NM_OUT -m set --match-set nm_active dst -j NFLOG --nflog-prefix nm:drop:ban:output --nflog-group 100\n-A NM_OUT -m set --match-set nm_active dst -j DROP\n")
	for _, v := range []struct{ hook, chain string }{{"INPUT", "NM_IN"}, {"OUTPUT", "NM_OUT"}} {
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "-A "+v.hook+" -j "+v.chain {
				fmt.Fprintf(&s, "-D %s -j %s\n", v.hook, v.chain)
			}
		}
		fmt.Fprintf(&s, "-I %s 1 -j %s\n", v.hook, v.chain)
	}
	s.WriteString("COMMIT\n")
	_, err = c.execute(s.String(), tool+"-restore", "-w", "5", "--noflush")
	return err
}
func (c *Controller) iptablesAlive() bool {
	raw, err := c.execute("", "ipset", "save", activeSet)
	if err != nil {
		return false
	}
	var children []string
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "add" && f[1] == activeSet {
			if !ownedSet(f[2]) {
				return false
			}
			children = append(children, f[2])
		}
	}
	if len(children) != 2 {
		return false
	}
	actual := map[string]bool{}
	for _, child := range children {
		raw, err = c.execute("", "ipset", "save", child)
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 || f[0] != "add" {
				continue
			}
			px, err := netip.ParsePrefix(f[2])
			if err != nil {
				ip, e := netip.ParseAddr(f[2])
				if e != nil {
					return false
				}
				px = netip.PrefixFrom(ip, ip.BitLen())
			}
			actual[px.Masked().String()] = true
		}
	}
	now := time.Now()
	entries, err := fallbackEntries(c.lastPolicy, now)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		key := entry.net.String()
		if !actual[key] && (entry.expiry == 0 || entry.expiry-now.UnixMilli() > 1000) {
			return false
		}
		delete(actual, key)
	}
	if len(actual) != 0 {
		return false
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		raw, err = c.execute("", tool+"-save", "-t", "filter")
		if err != nil {
			return false
		}
		own := []string{}
		first := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "-A NM_IN ") || strings.HasPrefix(line, "-A NM_OUT ") {
				own = append(own, strings.ReplaceAll(line, "\"", ""))
			}
			for _, chain := range []string{"INPUT", "OUTPUT"} {
				if strings.HasPrefix(line, "-A "+chain+" ") && first[chain] == "" {
					first[chain] = line
				}
			}
		}
		want := []string{"-A NM_IN -i lo -j RETURN", "-A NM_IN -m set --match-set nm_active src -j NFLOG --nflog-prefix nm:drop:ban:input --nflog-group 100", "-A NM_IN -m set --match-set nm_active src -j DROP", "-A NM_OUT -o lo -j RETURN", "-A NM_OUT -m set --match-set nm_active dst -j NFLOG --nflog-prefix nm:drop:ban:output --nflog-group 100", "-A NM_OUT -m set --match-set nm_active dst -j DROP"}
		if strings.Join(own, "\n") != strings.Join(want, "\n") || first["INPUT"] != "-A INPUT -j NM_IN" || first["OUTPUT"] != "-A OUTPUT -j NM_OUT" {
			return false
		}
	}
	return true
}

type denyEntry struct {
	net    netip.Prefix
	expiry int64
}

func fallbackEntries(p Policy, now time.Time) ([]denyEntry, error) {
	never := append([]netip.Prefix(nil), p.Never...)
	if p.Monitor.IsValid() {
		ip := p.Monitor.Unmap()
		never = append(never, netip.PrefixFrom(ip, ip.BitLen()))
	}
	protected, err := prefixes(never)
	if err != nil {
		return nil, err
	}
	entries := map[netip.Prefix]int64{}
	add := func(px netip.Prefix, expiry int64) {
		parts := []netip.Prefix{px.Masked()}
		for _, safe := range protected {
			var next []netip.Prefix
			for _, part := range parts {
				next = append(next, subtractPrefix(part, safe)...)
			}
			parts = next
		}
		for _, part := range parts {
			// hash:net cannot store /0.
			if part.Bits() == 0 {
				a, b := splitPrefix(part)
				parts2 := []netip.Prefix{a, b}
				for _, p2 := range parts2 {
					mergeExpiry(entries, p2, expiry)
				}
			} else {
				mergeExpiry(entries, part, expiry)
			}
		}
	}
	for _, px := range p.BlockNets {
		if !px.IsValid() || px.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid block prefix")
		}
		add(px, 0)
	}
	for _, b := range p.Blocks {
		if !b.IP.IsValid() || b.IP.Zone() != "" {
			return nil, fmt.Errorf("invalid ban address")
		}
		expiry := b.ExpiresAtMS
		if expiry == 0 && b.Timeout > 0 {
			expiry = now.Add(b.Timeout).UnixMilli()
		}
		if expiry < 0 {
			return nil, fmt.Errorf("invalid expiry")
		}
		if expiry > 0 && expiry <= now.UnixMilli() {
			continue
		}
		ip := b.IP.Unmap()
		add(netip.PrefixFrom(ip, ip.BitLen()), expiry)
	}
	var out []denyEntry
	for p, e := range entries {
		out = append(out, denyEntry{p, e})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].net.String() < out[j].net.String() })
	return out, nil
}
func mergeExpiry(m map[netip.Prefix]int64, p netip.Prefix, e int64) {
	old, ok := m[p]
	if !ok || e == 0 || old != 0 && e > old {
		m[p] = e
	}
}
func subtractPrefix(p, safe netip.Prefix) []netip.Prefix {
	if p.Addr().BitLen() != safe.Addr().BitLen() || !p.Overlaps(safe) {
		return []netip.Prefix{p}
	}
	if safe.Bits() <= p.Bits() {
		return nil
	}
	a, b := splitPrefix(p)
	return append(subtractPrefix(a, safe), subtractPrefix(b, safe)...)
}
func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	addr := p.Masked().Addr()
	bits := p.Bits()
	raw := addr.AsSlice()
	raw[bits/8] |= 1 << uint(7-bits%8)
	other, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(addr, bits+1), netip.PrefixFrom(other, bits+1)
}
