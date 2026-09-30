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
