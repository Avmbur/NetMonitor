package fw

import (
	"errors"
	"net/netip"
	"netmonitor/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestApplicationFailureIsReturnedWithoutFallback(t *testing.T) {
	boom := errors.New("operation not permitted")
	calls := 0
	c := &Controller{backend: "nftables", execute: func(input, name string, args ...string) ([]byte, error) {
		calls++
		if name != "nft" || strings.Join(args, " ") != "-f -" || !strings.Contains(input, "flush chain inet netmon input") {
			t.Fatal("not an atomic nft batch")
		}
		if strings.Contains(input, "flush ruleset") {
			t.Fatal("modifies foreign firewall")
		}
		return nil, boom
	}}
	if err := c.Apply(Policy{Mode: "learn"}); !errors.Is(err, boom) {
		t.Fatalf("lost backend error: %v", err)
	}
	if calls != 1 || c.Backend() != "nftables" {
		t.Fatal("backend changed on failure")
	}
}
func TestUnsupportedBackendDoesNotMutate(t *testing.T) {
	for _, backend := range []string{"unknown", "iptables"} {
		c := &Controller{backend: backend, execute: func(string, string, ...string) ([]byte, error) { t.Fatal("unsafe fallback executed"); return nil, nil }}
		if err := c.Apply(Policy{Mode: "learn"}); err == nil {
			t.Fatal("unsupported backend reported success")
		}
	}
}
func TestScriptDeduplicatesAndPreservesExpiryAndProtection(t *testing.T) {
	now := time.UnixMilli(100000)
	ip := netip.MustParseAddr("198.18.0.2")
	p := Policy{Mode: "allow", Monitor: netip.MustParseAddr("fd00::1"), Never: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")},
		Blocks:    []Desired{{IP: ip, ExpiresAtMS: 100500}, {IP: ip, ExpiresAtMS: 101500}, {IP: netip.MustParseAddr("198.18.0.3"), ExpiresAtMS: 99999}},
		BlockNets: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16"), netip.MustParsePrefix("198.18.0.0/24")},
	}
	s, err := nftScript(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(s, "add element inet netmon ban4") != 1 || !strings.Contains(s, "timeout 1500ms") {
		t.Fatal("duplicate/expired ban or refreshed TTL")
	}
	if strings.Count(s, "add element inet netmon gblock4") != 1 {
		t.Fatal("overlapping intervals")
	}
	if strings.Index(s, "ip6 saddr fd00::1/128 accept") > strings.Index(s, "ip6 saddr @ban6 ") {
		t.Fatal("protected monitor after ban")
	}
	if strings.Index(s, "ip saddr @ban4 ") > strings.Index(s, "ct state established") {
		t.Fatal("established traffic bypasses ban")
	}
	if strings.Contains(s, "flush set inet netmon learn") {
		t.Fatal("policy refresh erased learning attempts")
	}
}

// A precise ban keeps every condition, outranks ordinary rules and is refused
// outright by a backend that cannot execute it.
func TestPreciseBanKeepsConditionsAndOutranksRules(t *testing.T) {
	now := time.UnixMilli(100000)
	p := Policy{Mode: "learn", Managed: true, Monitor: netip.MustParseAddr("198.18.0.1"), MonitorPort: 8443,
		Blocks: []Desired{
			{BlockID: "b1", IP: netip.MustParseAddr("198.18.0.2"), Protocol: "tcp", Port: 443, Direction: "out", ExpiresAtMS: 160000},
			{BlockID: "b2", Protocol: "tcp", LocalPort: 8080, Direction: "in", ExpiresAtMS: 160000},
		},
		Rules: []policy.Rule{{ID: "r1", Enabled: true, Action: "allow", Order: 1,
			Match: policy.Match{Protocol: "tcp", Direction: "out", Networks: []string{"198.18.0.2/32"}, RemotePort: 443}}},
	}
	s, err := nftScript(p, now)
	if err != nil {
		t.Fatal(err)
	}
	drop := strings.Index(s, "nm:drop:deny:ban:b1")
	if drop < 0 || !strings.Contains(s, "ip daddr 198.18.0.2/32") || !strings.Contains(s, "tcp dport 443") {
		t.Fatalf("ban condition lost:\n%s", s)
	}
	if !strings.Contains(s, "meta time < 160") {
		t.Fatal("absolute expiry not handed to the kernel")
	}
	if allow := strings.Index(s, "ip daddr 198.18.0.2/32 meta l4proto tcp tcp dport 443 accept"); allow < 0 || allow < drop {
		t.Fatalf("allowing rule overrides the manual ban:\n%s", s)
	}
	local := strings.Index(s, "nm:drop:deny:ban:b2")
	if local < 0 || !strings.Contains(s, "input ct direction original meta l4proto tcp tcp dport 8080 meta time < 160 log") {
		t.Fatalf("local port ban lost its target:\n%s", s)
	}
	if !strings.Contains(s, "tcp dport 8443 accept") || !strings.Contains(s, "tcp sport 8443 accept") {
		t.Fatal("monitor port must stay reachable in learn")
	}
	if strings.Contains(s, "add element inet netmon ban4") {
		t.Fatal("precise ban degraded to a whole-address set element")
	}
	c := &Controller{backend: "iptables", execute: func(string, string, ...string) ([]byte, error) {
		t.Fatal("precise ban silently weakened")
		return nil, nil
	}}
	if err := c.Apply(Policy{Mode: "allow", Blocks: p.Blocks}); err == nil {
		t.Fatal("iptables reported a precise ban as applied")
	}
}

func TestProcessBindingAndOnceKeepPrecision(t *testing.T) {
	uid := 33
	r := policy.Rule{ID: "proc", Enabled: true, Action: "allow",
		Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 80, Networks: []string{"198.18.0.2/32"},
			Bindings: []policy.Binding{{Host: "h1", Name: "nginx", Cgroup: "system.slice/nginx.service", Path: "/usr/sbin/nginx", UID: &uid}}}}
	once := policy.Rule{ID: "once1", Enabled: true, Action: "allow", Once: true,
		Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 443, Networks: []string{"198.18.0.3/32"}}}
	s, err := nftScript(Policy{Mode: "learn", Managed: true, Rules: []policy.Rule{r, once}}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `socket cgroupv2 level 2 "system.slice/nginx.service"`) {
		t.Fatalf("cgroup lost:\n%s", s)
	}
	if strings.Contains(s, "meta skuid") {
		t.Fatal("process binding widened to uid")
	}
	if !strings.Contains(s, "ip daddr 198.18.0.2/32") || !strings.Contains(s, "socket cgroupv2") {
		t.Fatal("process allow degraded to address")
	}
	inb := r
	inb.ID = "inb"
	inb.Match.Direction = "in"
	inb.Match.RemotePort = 0
	inb.Match.LocalPort = 80
	sIn, err := nftScript(Policy{Mode: "learn", Managed: true, Rules: []policy.Rule{inb}}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sIn, "socket cgroupv2") {
		t.Fatal("inbound process used a socket match")
	}
	if !strings.Contains(sIn, "tcp dport 80") {
		t.Fatal("inbound process dropped the listen port")
	}
	set := onceSetName(once.ID)
	if !strings.Contains(s, "add set inet netmon "+set+" { typeof ct id; size 1; flags dynamic; }") || !strings.Contains(s, "add @"+set+" { ct id }") {
		t.Fatalf("once set missing:\n%s", s)
	}
	spent := once
	spent.OnceUsed = true
	s2, err := nftScript(Policy{Mode: "learn", Managed: true, Rules: []policy.Rule{spent}}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s2, "add @"+onceSetName(once.ID)+" { ct id }") {
		t.Fatal("spent once dropped the first flow")
	}
	if strings.Contains(s2, "destroy set inet netmon "+onceSetName(once.ID)) {
		t.Fatal("spent once set recreated empty")
	}
	other := r
	other.Match.Bindings = []policy.Binding{{Host: "h2", Name: "nginx", Path: "/usr/bin/nginx", UID: &uid}}
	s3, err := nftScript(Policy{Mode: "learn", Managed: true, Rules: []policy.Rule{other}}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s3, "198.18.0.2/32") {
		t.Fatal("unenforceable process allow widened to address")
	}
}

func TestObserveAcceptsAndAlertDrops(t *testing.T) {
	g := policy.Rule{ID: "g", Name: "телеметрия", Enabled: true, Action: "observe", Match: policy.Match{Networks: []string{"198.18.9.0/24"}}}
	s, err := nftScript(Policy{Mode: "learn", Managed: true, Groups: []policy.Rule{g}}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip daddr 198.18.9.0/24 accept") {
		t.Fatalf("observe dropped:\n%s", s)
	}
	if strings.Contains(s, "nm:drop:observe:") {
		t.Fatal("observe logged a drop")
	}
	g.Action = "alert"
	s, err = nftScript(Policy{Mode: "learn", Managed: true, Groups: []policy.Rule{g}}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "nm:drop:alert:g") {
		t.Fatalf("alert passed:\n%s", s)
	}
	g.Action = "deny"
	s, err = nftScript(Policy{Mode: "learn", Managed: true, Groups: []policy.Rule{g}}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "nm:drop:deny:g") {
		t.Fatalf("block passed:\n%s", s)
	}
}

func TestLearnReplySkipsQuestion(t *testing.T) {
	silent := "add rule inet netmon input ct direction reply drop\n"
	for _, mode := range []string{"learn", "block"} {
		s, err := nftScript(Policy{Mode: mode, Managed: true}, time.UnixMilli(1))
		if err != nil {
			t.Fatal(mode, err)
		}
		reply := strings.Index(s, silent)
		learn := strings.Index(s, "add @learn4i")
		if reply < 0 || learn < 0 || reply > learn {
			t.Fatalf("%s reply not before learn set:\n%s", mode, s)
		}
		line := s[reply : reply+len(silent)-1]
		if strings.Contains(line, "log group") {
			t.Fatalf("%s reply drop is logged: %s", mode, line)
		}
		if !strings.Contains(s, "add @learn4o") {
			t.Fatal(mode, "outbound learn missing")
		}
	}
	s, err := nftScript(Policy{Mode: "allow", Managed: true}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "ct direction reply drop") {
		t.Fatal("allow drops replies")
	}
}

func TestICMPv4ErrorsOnlyRelated(t *testing.T) {
	rule := "meta nfproto ipv4 ct state related icmp type { 3, 11, 12 } accept"
	for _, mode := range []string{"learn", "block", "allow"} {
		s, err := nftScript(Policy{Mode: mode, Managed: true, Blocks: []Desired{{IP: netip.MustParseAddr("203.0.113.9")}}}, time.UnixMilli(1))
		if err != nil {
			t.Fatal(mode, err)
		}
		for _, ch := range []string{"input", "output"} {
			at := strings.Index(s, "add rule inet netmon "+ch+" "+rule+"\n")
			ban := strings.Index(s, "add rule inet netmon "+ch+" ip "+map[string]string{"input": "saddr", "output": "daddr"}[ch]+" @ban4")
			if at < 0 || ban < 0 || ban > at {
				t.Fatalf("%s %s: related ICMPv4 missing or before bans:\n%s", mode, ch, s)
			}
			if mode != "allow" {
				reply := strings.Index(s, "ct direction reply drop")
				learn := strings.Index(s, "add @learn4"+ch[:1])
				if at > reply || at > learn {
					t.Fatalf("%s %s: related ICMPv4 after drop:\n%s", mode, ch, s)
				}
			}
		}
		if strings.Contains(s, "icmp type { 3, 11, 12 } accept") && strings.Count(s, "icmp type { 3, 11, 12 }") != strings.Count(s, "ct state related icmp type { 3, 11, 12 }") {
			t.Fatalf("%s: ICMPv4 errors accepted without related:\n%s", mode, s)
		}
	}
}

func TestForwardDockerOrder(t *testing.T) {
	bridge := netip.MustParsePrefix("172.17.0.0/16")
	p := Policy{
		Mode: "learn", Managed: true,
		DockerIfaces: []string{"br-ab", "docker0"},
		DockerNets:   []netip.Prefix{bridge},
		Never:        []netip.Prefix{netip.MustParsePrefix("192.0.2.9/32")},
		Blocks: []Desired{
			{BlockID: "b", IP: netip.MustParseAddr("203.0.113.9"), Port: 25, Protocol: "tcp", Direction: "out"},
			{BlockID: "p", LocalPort: 8081, Protocol: "tcp", Direction: "in"},
			{BlockID: "all", IP: netip.MustParseAddr("203.0.113.7")},
		},
		Groups: []policy.Rule{{ID: "g", Enabled: true, Action: "alert", Match: policy.Match{Direction: "in", Networks: []string{"198.51.100.0/24"}}}},
		Rules: []policy.Rule{
			{ID: "web", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 8080}},
			{ID: "dns", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 53}},
			{ID: "https", Enabled: true, Action: "allow", Match: policy.Match{Protocol: "tcp", AnyPort: 443}},
			{ID: "proc", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Bindings: []policy.Binding{{Path: "/bin/curl"}}}},
		},
	}
	s, err := nftScript(p, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	chain := func(name string) string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "add rule inet netmon "+name+" ") {
				out = append(out, strings.TrimPrefix(l, "add rule inet netmon "+name+" "))
			}
		}
		return strings.Join(out, "\n")
	}
	inOrder := func(text string, parts ...string) {
		t.Helper()
		at := 0
		for _, part := range parts {
			i := strings.Index(text[at:], part)
			if i < 0 {
				t.Fatalf("missing or out of order %q in\n%s", part, text)
			}
			at += i + len(part)
		}
	}
	inOrder(chain("forward"),
		`iifname { "br-ab", "docker0" } oifname { "br-ab", "docker0" } accept`,
		`ip saddr { 172.17.0.0/16 } ip daddr { 172.17.0.0/16 } accept`,
		`ct original ip saddr { 172.17.0.0/16 } jump fwd_out`,
		`ct reply ip saddr { 172.17.0.0/16 } jump fwd_in`)
	if strings.Contains(chain("forward"), "drop") {
		t.Fatal("forward base chain must only dispatch:\n" + chain("forward"))
	}
	out, in := chain("fwd_out"), chain("fwd_in")
	// «Не блокировать» до банов; баны по внешнему адресу из conntrack, без имён мостов (veth).
	inOrder(out, "ct original ip daddr 192.0.2.9/32 accept", "ct original ip daddr @ban4", "udp ct original proto-dst 53 accept", "ct direction reply drop\n", "nm:drop:policy:fwd_out")
	inOrder(in, "ct original ip saddr 192.0.2.9/32 accept", "ct original ip saddr @ban4", "nm:drop:alert:g", "tcp ct original proto-dst 8080 accept", "ct direction reply drop\n", "nm:drop:policy:fwd_in")
	if strings.Contains(out+in, "ifname") {
		t.Fatal("branch depends on interface names")
	}
	// Бан с направлением — только в своей ветке.
	if !strings.Contains(out, "ct original proto-dst 25") || strings.Contains(in, "proto-dst 25") || strings.Contains(in, "proto-src 25") {
		t.Fatal("outbound port ban leaked:\n" + in)
	}
	if !strings.Contains(in, "ct original proto-dst 8081") || strings.Contains(out, "8081") {
		t.Fatal("inbound port ban leaked:\n" + out)
	}
	// «Любой порт» — обе стороны кортежа в обеих ветках.
	for _, br := range []string{out, in} {
		if !strings.Contains(br, "ct original proto-src 443 accept") || !strings.Contains(br, "ct original proto-dst 443 accept") {
			t.Fatal("any port lost a side:\n" + br)
		}
	}
	if strings.Contains(out+in, "curl") {
		t.Fatal("process rule leaked into forward")
	}
	allow, err := nftScript(Policy{Mode: "allow", Managed: true, DockerIfaces: p.DockerIfaces, DockerNets: p.DockerNets, Blocks: p.Blocks}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(allow, `fwd_out log group 100 prefix "nm:drop:policy:fwd_out"`) || strings.Contains(allow, `fwd_in log group 100 prefix "nm:drop:policy:fwd_in"`) || strings.Contains(allow, "ct direction reply drop") {
		t.Fatal("allow has a general forward drop")
	}
	if !strings.Contains(allow, `fwd_out ct original ip daddr 203.0.113.9/32 meta l4proto tcp ct original proto-dst 25 log group 100 prefix "nm:drop:deny:ban:b"`) || !strings.Contains(allow, "fwd_out ct original ip daddr @ban4") {
		t.Fatal("allow dropped the explicit ban")
	}
	bare, err := nftScript(Policy{Mode: "learn", Managed: true}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bare, "add rule inet netmon forward accept\n") || strings.Contains(bare, "jump fwd_out") {
		t.Fatal("no bridges should only pass forward")
	}
}

func TestQuarantineContainerToHostIsDNS(t *testing.T) {
	s, err := nftScript(Policy{Mode: "quarantine", Managed: true, DockerIfaces: []string{"docker0"}, MonitorPort: 8443, Never: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, `iifname { "docker0" } accept`) {
		t.Fatal("quarantine still accepts every container to host packet")
	}
	if !strings.Contains(s, `iifname { "docker0" } ct direction reply accept`) || !strings.Contains(s, `iifname { "docker0" } meta l4proto { tcp, udp } th dport 53 accept`) {
		t.Fatal("quarantine dns or reply missing", s)
	}
	if !strings.Contains(s, `oifname { "docker0" } accept`) {
		t.Fatal("host to container closed in quarantine")
	}
	ordered := []string{
		`input iifname { "docker0" } ct direction reply accept`,
		`input iifname { "docker0" } meta l4proto { tcp, udp } th dport 53 accept`,
		`input iifname { "docker0" } ip6 hoplimit 255 icmpv6 type { 135, 136 } accept`,
		`input iifname { "docker0" } log group 100 prefix "nm:drop:policy:input" snaplen 256 queue-threshold 1 drop`,
		`input tcp dport 8443 accept`,
		`input ip saddr 172.17.0.0/16 accept`,
	}
	previous := -1
	for _, rule := range ordered {
		at := strings.Index(s, rule)
		if at <= previous {
			t.Fatalf("missing or misplaced quarantine rule %q\n%s", rule, s)
		}
		previous = at
	}
	open, err := nftScript(Policy{Mode: "learn", Managed: true, DockerIfaces: []string{"docker0"}}, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(open, `iifname { "docker0" } accept`) {
		t.Fatal("learn must still pass container to host")
	}
}

func TestShieldClosesStreetInbound(t *testing.T) {
	s, err := nftScript(Policy{Mode: "shield", Managed: true}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip saddr != { 10.0.0.0/8") || !strings.Contains(s, "ct direction original ct state new log group 100") {
		t.Fatal("shield inbound missing", s)
	}
	if strings.Contains(s, "add rule inet netmon output drop") || strings.Contains(s, "add rule inet netmon input log group 100 prefix \"nm:drop:policy:input\" snaplen 256 queue-threshold 1 drop\n") {
		t.Fatal("shield must not close everything", s)
	}
}

// Шторм не зависит от режима и стоит раньше правил: «SSH для всех» новые
// входы с улицы не открывает, прямо названный адрес — открывает.
func TestStormAnyModeBeforeRules(t *testing.T) {
	sshAll := policy.Rule{ID: "ssh-all", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 22}}
	named := policy.Rule{ID: "office", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Networks: []string{"198.51.100.7"}}}
	anyNet := policy.Rule{ID: "world", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Networks: []string{"0.0.0.0/0"}}}
	for _, mode := range []string{"learn+storm", "block+storm", "allow+storm", "shield"} {
		s, err := nftScript(Policy{Mode: mode, Managed: true, Rules: []policy.Rule{sshAll, named, anyNet}}, time.UnixMilli(100000))
		if err != nil {
			t.Fatal(mode, err)
		}
		storm := strings.Index(s, "ip saddr != @stormok4 ct direction original ct state new")
		ssh := strings.Index(s, "tcp dport 22")
		if storm < 0 || ssh < 0 || storm > ssh {
			t.Fatalf("%s: шторм должен стоять до правил (storm=%d ssh=%d)\n%s", mode, storm, ssh, s)
		}
		if !strings.Contains(s, "add element inet netmon stormok4 { 198.51.100.7/32 }") || strings.Contains(s, "stormok4 { 0.0.0.0/0 }") {
			t.Fatalf("%s: в исключениях шторма только названные адреса\n%s", mode, s)
		}
	}
	s, err := nftScript(Policy{Mode: "learn", Managed: true, Rules: []policy.Rule{sshAll}}, time.UnixMilli(100000))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "@stormok4 ct direction") {
		t.Fatal("без шторма правила шторма нет", s)
	}
	if b, st := SplitMode("learn+storm"); b != "learn" || !st {
		t.Fatal(b, st)
	}
	if b, st := SplitMode("shield"); b != "allow" || !st {
		t.Fatal(b, st)
	}
}

func TestPortWithAnyProtocolCoversTCPAndUDP(t *testing.T) {
	r := policy.Rule{ID: "r", Enabled: true, Action: "deny", Hosts: []string{"h"}, Match: policy.Match{Direction: "out", Protocol: "any", RemotePort: 5432}}
	if err := policy.Validate(r); err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := emitPolicyRules([]policy.Rule{r}, func(ch, line string) { lines = append(lines, ch+": "+line) }); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "output: ct direction original meta l4proto { tcp, udp } th dport 5432") || strings.Contains(joined, "any") {
		t.Fatal(joined)
	}
	r.Match.Protocol = "icmp"
	if policy.Validate(r) == nil {
		t.Fatal("icmp with a port accepted")
	}
}
