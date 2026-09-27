package fw

import (
	"fmt"
	"net/netip"
	"netmonitor/internal/policy"
	"sort"
	"strings"
	"time"
)

// SplitMode отделяет шторм от режима сервера: «learn+storm», «block+storm»,
// «allow+storm» и прежний «shield» (= разрешить в шторм). Реакция на атаку
// от режима не зависит, режим решает только, что делать с неизвестным.
func SplitMode(m string) (base string, storm bool) {
	if m == "shield" {
		return "allow", true
	}
	if b, ok := strings.CutSuffix(m, "+storm"); ok {
		return b, true
	}
	return m, false
}

// stormNamed — источники, прямо названные в разрешающих правилах и группах:
// шторм их не режет, дальше они идут по обычному порядку правил. Правило
// «для всех» (без адресов или 0.0.0.0/0) в шторм не действует.
func stormNamed(rs ...[]policy.Rule) []netip.Prefix {
	var out []netip.Prefix
	for _, list := range rs {
		for _, r := range list {
			if !r.Enabled || r.Action != "allow" || r.Match.Direction == "out" {
				continue
			}
			for _, n := range r.Match.Networks {
				px, err := netip.ParsePrefix(n)
				if err != nil {
					a, e := netip.ParseAddr(n)
					if e != nil {
						continue
					}
					a = a.Unmap()
					px = netip.PrefixFrom(a, a.BitLen())
				}
				if px.Bits() == 0 || px.Addr().Is4In6() {
					continue
				}
				out = append(out, px.Masked())
			}
		}
	}
	return out
}

func nftScript(p Policy, now time.Time) (string, error) {
	if p.Mode == "" {
		p.Mode = "allow"
	}
	mode, storm := SplitMode(p.Mode)
	p.Mode = mode
	quarantine := p.Mode == "quarantine"
	if quarantine {
		storm = false
	}
	if quarantine {
		p.Mode = "block"
		p.Rules = nil
		p.Groups = nil
		p.AllowNets = nil
		p.BlockNets = nil
	}
	if p.Mode != "allow" && p.Mode != "learn" && p.Mode != "block" {
		return "", fmt.Errorf("unsupported mode %q", p.Mode)
	}
	var s strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&s, format+"\n", args...) }
	line("add table inet netmon")
	// Recreate our base chains inside the same transaction, including hook/priority.
	for _, ch := range []string{"input", "output"} {
		line("add chain inet netmon %s", ch)
		line("flush chain inet netmon %s", ch)
		line("delete chain inet netmon %s", ch)
	}
	for _, v := range []struct{ name, kind, flags string }{
		{"ban4", "ipv4_addr", "timeout"}, {"ban6", "ipv6_addr", "timeout"},
		{"gblock4", "ipv4_addr", "interval"}, {"gblock6", "ipv6_addr", "interval"},
		{"allow4", "ipv4_addr", "interval"}, {"allow6", "ipv6_addr", "interval"},
		{"stormok4", "ipv4_addr", "interval"}, {"stormok6", "ipv6_addr", "interval"},
	} {
		line("destroy set inet netmon %s", v.name)
		line("add set inet netmon %s { type %s; flags %s; }", v.name, v.kind, v.flags)
		line("flush set inet netmon %s", v.name)
	}
	for _, family := range []string{"4", "6"} {
		typ := "ipv4_addr"
		if family == "6" {
			typ = "ipv6_addr"
		}
		for _, dir := range []string{"i", "o"} {
			// Keep collected attempts across policy refreshes.
			line("add set inet netmon learn%s%s { type %s . inet_proto . inet_service; flags timeout; timeout 120s; }", family, dir, typ)
		}
	}
	for _, r := range p.Rules {
		if !r.Enabled || !r.Once || policy.Inert(r) {
			continue
		}
		name := onceSetName(r.ID)
		line("add set inet netmon %s { typeof ct id; size 1; flags dynamic; }", name)
	}
	for _, ch := range []string{"input", "output"} {
		line("add chain inet netmon %s { type filter hook %s priority -150; policy accept; }", ch, ch)
		line("flush chain inet netmon %s", ch)
	}
	add := func(ch, rule string) {
		if !strings.Contains(rule, "log group") && (rule == "drop" || strings.HasSuffix(rule, " drop")) {
			tag := "policy"
			if strings.Contains(rule, "@ban") {
				tag = "ban"
			}
			rule = strings.TrimSuffix(rule, "drop") + fmt.Sprintf("log group 100 prefix %q snaplen 256 queue-threshold 1 drop", "nm:drop:"+tag+":"+ch)
		}
		line("add rule inet netmon %s %s", ch, rule)
	}
	add("input", "iifname lo accept")
	add("output", "oifname lo accept")
	if p.MonitorPort > 0 && p.MonitorPort <= 65535 {
		add("input", fmt.Sprintf("tcp dport %d accept", p.MonitorPort))
		add("output", fmt.Sprintf("tcp sport %d accept", p.MonitorPort))
	}
	// Protected addresses precede every block, including containing prefixes.
	never := append([]netip.Prefix(nil), p.Never...)
	if p.Monitor.IsValid() {
		ip := p.Monitor.Unmap()
		never = append(never, netip.PrefixFrom(ip, ip.BitLen()))
	}
	ns, err := prefixes(never)
	if err != nil {
		return "", err
	}
	for _, px := range ns {
		family := "ip"
		if px.Addr().Is6() {
			family = "ip6"
		}
		add("input", family+" saddr "+px.String()+" accept")
		add("output", family+" daddr "+px.String()+" accept")
	}
	if quarantine {
		for _, proto := range []string{"tcp", "udp"} {
			if err := emitPolicyRules([]policy.Rule{{ID: "quarantine-dns", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: proto, RemotePort: 53}}}, add); err != nil {
				return "", err
			}
		}
		if err := emitPolicyRules([]policy.Rule{{ID: "quarantine-ntp", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 123}}}, add); err != nil {
			return "", err
		}
	}
	for _, b := range p.Blocks {
		if preciseBlock(b) {
			if err := emitPolicyRules([]policy.Rule{banRule(b, now)}, add); err != nil {
				return "", err
			}
		}
	}
	for _, set := range []string{"ban", "gblock"} {
		add("input", "ip saddr @"+set+"4 drop")
		add("output", "ip daddr @"+set+"4 drop")
		add("input", "ip6 saddr @"+set+"6 drop")
		add("output", "ip6 daddr @"+set+"6 drop")
	}
	if storm {
		// Шторм — до правил: «SSH для всех» и прочие правила без адреса новые
		// входы с улицы не открывают. Проходят локальная сеть, «Не блокировать»
		// (выше), ответы на свои соединения и адреса, прямо названные в
		// разрешающих правилах и группах (@stormok, дальше — обычный порядок).
		add("input", "ip saddr != { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } ip saddr != @stormok4 ct direction original ct state new drop")
		add("input", "ip6 saddr != { ::1, fc00::/7, fe80::/10 } ip6 saddr != @stormok6 ct direction original ct state new drop")
	}
	if p.Managed {
		if err := emitPolicyRules(p.Groups, add); err != nil {
			return "", err
		}
		if err := emitPolicyRules(p.Rules, add); err != nil {
			return "", err
		}
	}
	// Legacy snapshots retain their service rules during the protocol transition.
	if !p.Managed {
		// A ban also stops established traffic, independent of conntrack deletion.
		add("input", "ct state established,related accept")
		add("output", "ct state established,related accept")
		add("input", "tcp dport 22 accept")
		add("output", "udp dport 53 accept")
		add("output", "tcp dport 53 accept")
	}
	// Client service traffic only; this does not open the LAN or arbitrary IPv6.
	add("output", "meta nfproto ipv4 udp sport 68 udp dport 67 accept")
	add("input", "meta nfproto ipv4 udp sport 67 udp dport 68 accept")
	add("output", "meta nfproto ipv6 udp sport 546 udp dport 547 accept")
	add("input", "meta nfproto ipv6 udp sport 547 udp dport 546 accept")
	for _, ch := range []string{"input", "output"} {
		add(ch, "icmpv6 type { 1, 2, 3, 4 } accept")
		add(ch, "ip6 hoplimit 255 icmpv6 type { 133, 134, 135, 136 } accept")
		add(ch, "ip6 hoplimit 1 ip6 saddr { fe80::/10, ::/128 } icmpv6 type { 130, 131, 132, 143 } accept")
	}
	if !p.Managed {
		add("output", "udp dport 123 accept")
	}
	for _, family := range []string{"4", "6"} {
		ip := "ip"
		if family == "6" {
			ip = "ip6"
		}
		add("input", ip+" saddr @allow"+family+" accept")
		add("output", ip+" daddr @allow"+family+" accept")
	}
	if p.Mode == "learn" || p.Mode == "block" {
		for _, family := range []string{"4", "6"} {
			ip := "ip"
			if family == "6" {
				ip = "ip6"
			}
			for _, v := range []struct{ ch, dir, addr string }{{"input", "i", "saddr"}, {"output", "o", "daddr"}} {
				for _, proto := range []string{"tcp", "udp"} {
					add(v.ch, fmt.Sprintf("meta nfproto ipv%s meta l4proto %s add @learn%s%s { %s %s . meta l4proto . %s dport } drop", family, proto, family, v.dir, ip, v.addr, proto))
				}
				proto := "icmp"
				if family == "6" {
					proto = "ipv6-icmp"
				}
				add(v.ch, fmt.Sprintf("meta nfproto ipv%s meta l4proto %s add @learn%s%s { %s %s . meta l4proto . 0 } drop", family, proto, family, v.dir, ip, v.addr))
			}
		}
		add("input", "drop")
		add("output", "drop")
	}
	for _, v := range []struct {
		name string
		nets []netip.Prefix
	}{{"gblock", p.BlockNets}, {"allow", p.AllowNets}, {"stormok", stormNamed(p.Groups, p.Rules)}} {
		ps, err := prefixes(v.nets)
		if err != nil {
			return "", err
		}
		for _, px := range ps {
			family := "4"
			if px.Addr().Is6() {
				family = "6"
			}
			line("add element inet netmon %s%s { %s }", v.name, family, px.String())
		}
	}
	// Multiple live bans may name one IP. Keep the longest lifetime.
	bans := map[netip.Addr]int64{}
	for _, b := range p.Blocks {
		if preciseBlock(b) {
			continue
		}
		if !b.IP.IsValid() || b.IP.Zone() != "" {
			return "", fmt.Errorf("invalid ban address")
		}
		ip := b.IP.Unmap()
		expiry := b.ExpiresAtMS
		if expiry == 0 && b.Timeout > 0 {
			expiry = now.Add(b.Timeout).UnixMilli()
		}
		if expiry < 0 {
			return "", fmt.Errorf("invalid ban expiry")
		}
		if expiry > 0 && expiry <= now.UnixMilli() {
			continue
		}
		if old, ok := bans[ip]; !ok || expiry == 0 || old != 0 && expiry > old {
			bans[ip] = expiry
		}
	}
	ips := make([]netip.Addr, 0, len(bans))
	for ip := range bans {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	for _, ip := range ips {
		family := "4"
		if ip.Is6() {
			family = "6"
		}
		ttl := ""
		if expiry := bans[ip]; expiry > 0 {
			ttl = fmt.Sprintf(" timeout %dms", expiry-now.UnixMilli())
		}
		line("add element inet netmon ban%s { %s%s }", family, ip.String(), ttl)
	}
	return s.String(), nil
}
func prefixes(in []netip.Prefix) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range in {
		if !p.IsValid() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid policy prefix %s", p)
		}
		p = p.Masked()
		contained := false
		for _, q := range out {
			if q.Contains(p.Addr()) && q.Bits() <= p.Bits() {
				contained = true
				break
			}
		}
		if contained {
			continue
		}
		kept := out[:0]
		for _, q := range out {
			if !p.Contains(q.Addr()) || p.Bits() > q.Bits() {
				kept = append(kept, q)
			}
		}
		out = append(kept, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
