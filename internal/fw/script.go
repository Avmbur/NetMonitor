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
	for _, ch := range []string{"input", "output", "forward", "fwd_out", "fwd_in"} {
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
	line("add chain inet netmon fwd_out")
	line("add chain inet netmon fwd_in")
	line("add chain inet netmon forward { type filter hook forward priority -150; policy accept; }")
	line("flush chain inet netmon forward")
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
	if set := ifaceSet(p.DockerIfaces); set != "" {
		// Хост → контейнер оставляем. Контейнер → хост в карантине — только DNS
		// и ответы на соединения, которые открыл сам хост.
		if quarantine {
			add("input", "iifname "+set+" ct direction reply accept")
			add("input", "iifname "+set+" meta l4proto { tcp, udp } th dport 53 accept")
			// Neighbor discovery is needed for DNS and host-initiated IPv6 traffic.
			add("input", "iifname "+set+" ip6 hoplimit 255 icmpv6 type { 135, 136 } accept")
			// Do not let later host exceptions reopen container access in quarantine.
			add("input", "iifname "+set+" drop")
		} else {
			add("input", "iifname "+set+" accept")
		}
		add("output", "oifname "+set+" accept")
	}
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
		// ICMP-ошибки IPv4 (недоступен, в том числе «нужна фрагментация»; TTL;
		// ошибка заголовка) — только к соединению, которое уже есть в conntrack.
		// Без этого разрешённый TCP теряет подбор MTU через туннели и VPN.
		add(ch, "meta nfproto ipv4 ct state related icmp type { 3, 11, 12 } accept")
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
		// Ответ на наше исходящее приходит на input как ct direction reply.
		// В набор и в NFLOG его не пишем: иначе UDP, TCP и ICMP дают ложный вход.
		// Пакет всё равно отбрасывается, уже без вопроса.
		line("add rule inet netmon input ct direction reply drop")
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
	if err = writeForward(p, quarantine, storm, now, line, add); err != nil {
		return "", err
	}
	return s.String(), nil
}

func ifaceSet(names []string) string {
	if len(names) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var list []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		list = append(list, n)
	}
	sort.Strings(list)
	if len(list) == 0 {
		return ""
	}
	quoted := make([]string, len(list))
	for i, n := range list {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func prefixList(nets []netip.Prefix, v6 bool) string {
	var parts []string
	seen := map[string]bool{}
	for _, n := range nets {
		if !n.IsValid() || n.Addr().Is6() != v6 {
			continue
		}
		s := n.Masked().String()
		if seen[s] {
			continue
		}
		seen[s] = true
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// writeForward фильтрует только границу контейнеров Docker с внешней сетью.
// Сторону соединения берём из кортежа conntrack, а не из имён интерфейсов:
// после DNAT пакет опубликованного порта уходит в veth, а не в мост.
func writeForward(p Policy, quarantine, storm bool, now time.Time, line func(string, ...any), add func(string, string)) error {
	set := ifaceSet(p.DockerIfaces)
	nets := map[string]string{"ip": prefixList(p.DockerNets, false), "ip6": prefixList(p.DockerNets, true)}
	if set == "" && nets["ip"] == "" && nets["ip6"] == "" {
		line("add rule inet netmon forward accept")
		return nil
	}
	// Контейнер ↔ контейнер решает Docker.
	if set != "" {
		add("forward", "iifname "+set+" oifname "+set+" accept")
	}
	for _, fam := range []string{"ip", "ip6"} {
		if n := nets[fam]; n != "" {
			add("forward", fam+" saddr { "+n+" } "+fam+" daddr { "+n+" } accept")
		}
	}
	// Начал контейнер — «исход»; ответил контейнер чужому — «вход». Остальное
	// (VPN, маршрутизация хоста) не наше: политика цепочки accept.
	for _, fam := range []string{"ip", "ip6"} {
		if n := nets[fam]; n != "" {
			add("forward", "ct original "+fam+" saddr { "+n+" } jump fwd_out")
			add("forward", "ct reply "+fam+" saddr { "+n+" } jump fwd_in")
		}
	}
	never := append([]netip.Prefix(nil), p.Never...)
	if p.Monitor.IsValid() {
		ip := p.Monitor.Unmap()
		never = append(never, netip.PrefixFrom(ip, ip.BitLen()))
	}
	ns, err := prefixes(never)
	if err != nil {
		return err
	}
	for _, br := range []struct {
		chain, remote string
		inbound       bool
	}{{"fwd_out", "daddr", false}, {"fwd_in", "saddr", true}} {
		remote := func(fam string) string { return "ct original " + fam + " " + br.remote }
		for _, px := range ns {
			fam := "ip"
			if px.Addr().Is6() {
				fam = "ip6"
			}
			add(br.chain, remote(fam)+" "+px.String()+" accept")
		}
		for _, b := range p.Blocks {
			if preciseBlock(b) {
				if err = emitForwardRules([]policy.Rule{banRule(b, now)}, br.chain, br.inbound, add); err != nil {
					return err
				}
			}
		}
		for _, name := range []string{"ban", "gblock"} {
			add(br.chain, remote("ip")+" @"+name+"4 drop")
			add(br.chain, remote("ip6")+" @"+name+"6 drop")
		}
		add(br.chain, "meta nfproto ipv4 ct state related icmp type { 3, 11, 12 } accept")
		add(br.chain, "meta nfproto ipv6 ct state related icmpv6 type { 1, 2, 3, 4 } accept")
		if storm && br.inbound {
			add(br.chain, "ct original ip saddr != { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } ct original ip saddr != @stormok4 ct direction original ct state new drop")
			add(br.chain, "ct original ip6 saddr != { ::1, fc00::/7, fe80::/10 } ct original ip6 saddr != @stormok6 ct direction original ct state new drop")
		}
		if quarantine {
			if !br.inbound {
				q := []policy.Rule{
					{ID: "quarantine-dns", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 53}},
					{ID: "quarantine-dns", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 53}},
					{ID: "quarantine-ntp", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 123}},
				}
				for _, r := range q {
					if err = emitForwardRules([]policy.Rule{r}, br.chain, false, add); err != nil {
						return err
					}
				}
			}
		} else {
			if err = emitForwardRules(p.Groups, br.chain, br.inbound, add); err != nil {
				return err
			}
			if err = emitForwardRules(p.Rules, br.chain, br.inbound, add); err != nil {
				return err
			}
		}
		add(br.chain, remote("ip")+" @allow4 accept")
		add(br.chain, remote("ip6")+" @allow6 accept")
		if p.Mode == "learn" || p.Mode == "block" {
			// Ответ на срезанное соединение — без журнала, иначе ложный вопрос.
			line("add rule inet netmon %s ct direction reply drop", br.chain)
			add(br.chain, "drop")
		}
	}
	return nil
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
