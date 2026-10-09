package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	pol "netmonitor/internal/policy"
)

func TestGroupNameCoversNewAddressWithoutQuestion(t *testing.T) {
	a := &Agent{managed: true, mode: "learn", hostID: "h"}
	a.groups = []pol.Rule{{
		ID: "ubuntu", Enabled: true, Action: "observe",
		Match: pol.Match{Names: []string{"motd.ubuntu.com"}, Networks: []string{}},
	}}
	if !a.questionLocked(pol.Contact{Host: "h", Direction: "out", Protocol: "tcp", RemoteIP: "34.244.58.147", RemotePort: 443}) {
		t.Fatal("unknown address must still ask")
	}
	if !mergeNamePrefix(a.groups, "motd.ubuntu.com", "34.244.58.147/32") {
		t.Fatal("name was not absorbed")
	}
	if a.questionLocked(pol.Contact{Host: "h", Direction: "out", Protocol: "tcp", RemoteIP: "34.244.58.147", RemotePort: 443}) {
		t.Fatal("observe group asked about its own name")
	}
}

func TestNameReachesGroupAndRule(t *testing.T) {
	groups := []pol.Rule{{ID: "g", Enabled: true, Action: "observe", Match: pol.Match{Names: []string{"*.ubuntu.com"}, Networks: []string{}}}}
	rules := []pol.Rule{{ID: "r", Enabled: true, Action: "deny", Match: pol.Match{Names: []string{"motd.ubuntu.com"}, Networks: []string{}}}}
	if !mergeNameEverywhere(groups, rules, "motd.ubuntu.com", "34.244.58.147/32") {
		t.Fatal("name was not absorbed")
	}
	if !slices.Contains(groups[0].Match.Networks, "34.244.58.147/32") || !slices.Contains(rules[0].Match.Networks, "34.244.58.147/32") {
		t.Fatalf("group %v rule %v", groups[0].Match.Networks, rules[0].Match.Networks)
	}
}

func TestAttachResolvedKeepsEveryAddressOfTheName(t *testing.T) {
	prev := lookupHostIPs
	stage := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")}
	var calls int
	lookupHostIPs = func(ctx context.Context, name string) ([]netip.Addr, error) {
		calls++
		if name != "cdn.example.test" {
			t.Fatalf("lookup %s", name)
		}
		return stage, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	rules := []pol.Rule{{
		ID: "r", Enabled: true, Action: "allow",
		Match: pol.Match{Names: []string{"cdn.example.test"}, Networks: []string{"203.0.113.10/32"}},
	}}
	out, rep := a.attachResolved(rules)
	if calls != 1 || len(rep) != 2 {
		t.Fatalf("calls=%d reports=%+v", calls, rep)
	}
	if len(out[0].Match.Networks) != 2 || out[0].Match.Networks[1] != "203.0.113.11/32" {
		t.Fatal(out[0].Match.Networks)
	}
	missed := rep[0]
	out, rep = a.attachResolved(rules)
	if calls != 1 || len(rep) != 0 || len(out[0].Match.Networks) != 2 {
		t.Fatalf("repeat calls=%d rep=%+v nets=%v", calls, rep, out[0].Match.Networks)
	}
	a.forgetReported(missed)
	a.nameMu.Lock()
	cached := a.resolved["cdn.example.test"]
	cached.at = time.Time{}
	a.resolved["cdn.example.test"] = cached
	a.nameMu.Unlock()
	stage = []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")}
	out, rep = a.attachResolved(rules)
	if calls != 2 || len(rep) != 2 || len(out[0].Match.Networks) != 3 {
		t.Fatalf("new calls=%d %+v %v", calls, rep, out[0].Match.Networks)
	}
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("dns down")
	}
	a.nameMu.Lock()
	cached = a.resolved["cdn.example.test"]
	cached.at = time.Time{}
	a.resolved["cdn.example.test"] = cached
	a.nameMu.Unlock()
	out, rep = a.attachResolved(rules)
	if len(rep) != 0 || len(out[0].Match.Networks) != 3 {
		t.Fatalf("failure dropped %v %+v", out[0].Match.Networks, rep)
	}
	wild := []pol.Rule{{Match: pol.Match{Names: []string{"*.example.test"}}}}
	if out, rep = a.attachResolved(wild); len(rep) != 0 || out[0].Match.Networks == nil || len(out[0].Match.Networks) != 0 {
		t.Fatal(rep, out[0].Match.Networks)
	}
}

func TestAttachResolvedUnresolvedNameOpensNothing(t *testing.T) {
	prev := lookupHostIPs
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("dns down") }
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	out, rep := a.attachResolved([]pol.Rule{{ID: "r", Enabled: true, Action: "allow", Match: pol.Match{Names: []string{"gone.example.test"}}}})
	if len(rep) != 0 || out[0].Match.Networks == nil || len(out[0].Match.Networks) != 0 {
		t.Fatalf("unresolved name widened: %#v %+v", out[0].Match.Networks, rep)
	}
}

func TestAttachResolvedOrderIsStable(t *testing.T) {
	prev := lookupHostIPs
	flip := false
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		flip = !flip
		if flip {
			return []netip.Addr{netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.10")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")}, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	rules := []pol.Rule{{ID: "r", Enabled: true, Action: "allow", Match: pol.Match{Names: []string{"cdn.example.test"}}}}
	first, _ := a.attachResolved(rules)
	a.nameMu.Lock()
	cached := a.resolved["cdn.example.test"]
	cached.at = time.Time{}
	a.resolved["cdn.example.test"] = cached
	a.nameMu.Unlock()
	second, _ := a.attachResolved(rules)
	if !slices.Equal(first[0].Match.Networks, second[0].Match.Networks) {
		t.Fatal(first[0].Match.Networks, second[0].Match.Networks)
	}
}

func TestAttachResolvedSlowNamesDoNotStarveOthers(t *testing.T) {
	prev := lookupHostIPs
	var calls []string
	lookupHostIPs = func(ctx context.Context, name string) ([]netip.Addr, error) {
		calls = append(calls, name)
		if name != "fast.example.test" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.12")}, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	names := []string{"slow1.example.test", "slow2.example.test", "fast.example.test"}
	rules := []pol.Rule{{Match: pol.Match{Names: names}}}
	var out []pol.Rule
	for range names {
		out, _ = a.attachResolved(rules)
		// Simulate a poll interval longer than nameRefresh, preserving age order.
		for name, c := range a.resolved {
			c.at = c.at.Add(-nameRefresh)
			a.resolved[name] = c
		}
	}
	if len(calls) < 3 || !slices.Equal(calls[:3], names) {
		t.Fatalf("starved names: %v", calls)
	}
	if !slices.Contains(out[0].Match.Networks, "203.0.113.12/32") {
		t.Fatalf("fast name never reached firewall: %v", out[0].Match.Networks)
	}
}

func TestAttachResolvedRetriesWithoutSameDNSAnswer(t *testing.T) {
	for _, mode := range []string{"cached", "failed", "changed", "removed"} {
		t.Run(mode, func(t *testing.T) {
			prev := lookupHostIPs
			t.Cleanup(func() { lookupHostIPs = prev })
			lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
			}
			a := &Agent{}
			rules := []pol.Rule{{Match: pol.Match{Names: []string{"cdn.example.test"}}}}
			_, reports := a.attachResolved(rules)
			if len(reports) != 1 {
				t.Fatal(reports)
			}
			missed := reports[0]
			a.forgetReported(missed)
			lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
				if mode == "cached" || mode == "removed" {
					t.Fatal("unexpected DNS lookup")
				}
				if mode == "changed" {
					return []netip.Addr{netip.MustParseAddr("203.0.113.11")}, nil
				}
				return nil, errors.New("dns down")
			}
			if mode != "cached" {
				c := a.resolved[missed.Name]
				c.at = time.Time{}
				a.resolved[missed.Name] = c
			}
			if mode == "removed" {
				rules = nil
			}
			_, reports = a.attachResolved(rules)
			if !slices.Contains(reports, missed) {
				t.Fatalf("lost failed report: %+v", reports)
			}
			// A second failed insertion must remain retryable too.
			a.forgetReported(missed)
			_, reports = a.attachResolved(rules)
			if len(reports) != 1 || reports[0] != missed {
				t.Fatalf("retry lost or duplicated: %+v", reports)
			}
			if _, reports = a.attachResolved(rules); len(reports) != 0 {
				t.Fatalf("successfully queued reports repeated: %+v", reports)
			}
		})
	}
}

func TestAttachResolvedKnownNamesTwoPerPoll(t *testing.T) {
	prev := lookupHostIPs
	var calls []string
	lookupHostIPs = func(_ context.Context, name string) ([]netip.Addr, error) {
		calls = append(calls, name)
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	names := []string{"a.example.test", "b.example.test", "c.example.test"}
	rules := []pol.Rule{{Match: pol.Match{Names: names}}}
	if _, _ = a.attachResolved(rules); len(calls) != 3 {
		t.Fatalf("new names %v", calls)
	}
	calls = nil
	a.nameMu.Lock()
	for name, c := range a.resolved {
		c.at = c.at.Add(-nameRefresh)
		a.resolved[name] = c
	}
	a.nameMu.Unlock()
	a.beginNamePoll()
	if _, _ = a.attachResolved(append(rules, pol.Rule{Match: pol.Match{Names: []string{"new.example.test"}}})); len(calls) != 3 || calls[0] != "new.example.test" {
		t.Fatalf("fresh name must jump the queue, two known follow: %v", calls)
	}
	a.endNamePoll()
	calls = nil
	a.beginNamePoll()
	if _, _ = a.attachResolved(rules); len(calls) != 1 {
		t.Fatalf("third known name waits for the next poll: %v", calls)
	}
	a.endNamePoll()
}

func TestAttachResolvedFailureKeepsAddresses(t *testing.T) {
	prev := lookupHostIPs
	var calls int
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	rules := []pol.Rule{{Match: pol.Match{Names: []string{"cdn.example.test"}}}}
	out, _ := a.attachResolved(rules)
	if calls != 1 || !slices.Contains(out[0].Match.Networks, "203.0.113.10/32") {
		t.Fatal(calls, out[0].Match.Networks)
	}
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("dns down")
	}
	age := func(d time.Duration) {
		t.Helper()
		a.nameMu.Lock()
		c := a.resolved["cdn.example.test"]
		c.at = time.Now().Add(-d)
		a.resolved["cdn.example.test"] = c
		a.nameMu.Unlock()
	}
	age(nameRefresh)
	out, _ = a.attachResolved(rules)
	if calls != 2 || !slices.Contains(out[0].Match.Networks, "203.0.113.10/32") {
		t.Fatalf("failure erased addresses calls=%d nets=%v", calls, out[0].Match.Networks)
	}
	if out, _ = a.attachResolved(rules); calls != 2 {
		t.Fatalf("retried before 30s: %d", calls)
	}
	age(nameRetrySoon)
	if out, _ = a.attachResolved(rules); calls != 3 || !slices.Contains(out[0].Match.Networks, "203.0.113.10/32") {
		t.Fatalf("30s retry calls=%d nets=%v", calls, out[0].Match.Networks)
	}
	age(nameRetrySoon)
	if _, _ = a.attachResolved(rules); calls != 3 {
		t.Fatalf("second failure retried before 2m: %d", calls)
	}
	age(nameRetryLater)
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("203.0.113.11")}, nil
	}
	out, rep := a.attachResolved(rules)
	if calls != 4 || !slices.Contains(out[0].Match.Networks, "203.0.113.11/32") || len(rep) != 1 {
		t.Fatalf("recovery calls=%d nets=%v rep=%+v", calls, out[0].Match.Networks, rep)
	}
}

func TestAttachResolvedSameNameOncePerPoll(t *testing.T) {
	prev := lookupHostIPs
	var calls int
	lookupHostIPs = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	t.Cleanup(func() { lookupHostIPs = prev })
	a := &Agent{}
	a.beginNamePoll()
	defer a.endNamePoll()
	rule := []pol.Rule{{Match: pol.Match{Names: []string{"motd.ubuntu.com"}}}}
	group := []pol.Rule{{Match: pol.Match{Names: []string{"motd.ubuntu.com"}}}}
	if _, _ = a.attachResolved(rule); calls != 1 {
		t.Fatal(calls)
	}
	if _, _ = a.attachResolved(group); calls != 1 {
		t.Fatalf("same name resolved twice in one poll: %d", calls)
	}
}
