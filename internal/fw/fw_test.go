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
