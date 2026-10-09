package policy

import (
	"net/netip"
	"testing"
)

func TestWithAdmittedCoversOnlyOnDemandRules(t *testing.T) {
	rs := []Rule{
		{ID: "svc", Enabled: true, Action: "allow", Match: Match{Direction: "out", Protocol: "tcp", RemotePort: 443, OnDemand: []string{"api.github.com"}}},
		{ID: "deny", Enabled: true, Action: "deny", Order: 1, Match: Match{Direction: "out", Protocol: "tcp", RemotePort: 22}},
	}
	c := Contact{Host: "h", Direction: "out", Protocol: "tcp", RemoteIP: "140.82.121.6", RemotePort: 443}
	if _, ok := Evaluate(rs, "h", c, 1); ok {
		t.Fatal("on-demand rule matched without admitted address")
	}
	got := WithAdmitted(rs, []netip.Addr{netip.MustParseAddr("140.82.121.6")})
	if d, ok := Evaluate(got, "h", c, 1); !ok || d.ID != "svc" {
		t.Fatalf("admitted address not covered: %v %v", d, ok)
	}
	if len(rs[0].Match.OnDemand) != 1 || rs[0].Match.Networks != nil {
		t.Fatal("source rules changed")
	}
	if got[1].Match.Networks != nil {
		t.Fatal("ordinary rule touched")
	}
	c.RemoteIP = "198.51.100.9"
	if _, ok := Evaluate(got, "h", c, 1); ok {
		t.Fatal("other address covered")
	}
}
