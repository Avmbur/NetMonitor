package server

import (
	"netmonitor/internal/policy"
	"netmonitor/internal/store"
	"testing"
)

func TestFlowVerdictObservePassesAndAlertCuts(t *testing.T) {
	now := store.NowMS()
	d := hostDecision{mode: "learn", groups: []policy.Rule{
		{ID: "g", Name: "телеметрия", Enabled: true, Action: "observe", Match: policy.Match{Networks: []string{"203.0.113.0/24"}}},
		{ID: "g2", Name: "cdn", Enabled: true, Action: "allow", Order: 5, Match: policy.Match{Networks: []string{"203.0.113.0/24"}}},
	}}
	name, st, detail := d.explain(policy.Contact{RemoteIP: "203.0.113.9", Host: "h"}, now)
	if name != "телеметрия" || st != "open" {
		t.Fatal(name, st)
	}
	if detail != "группы: телеметрия, cdn" {
		t.Fatal(detail)
	}
	d.groups[0].Action = "alert"
	name, st, _ = d.explain(policy.Contact{RemoteIP: "203.0.113.9", Host: "h"}, now)
	if name != "телеметрия" || st != "block" {
		t.Fatal(name, st)
	}
	if !d.needsQuestion(policy.Contact{RemoteIP: "203.0.113.9", Host: "h"}, now) {
		t.Fatal("alert must keep the question")
	}
	d.groups = nil
	d.rules = []policy.Rule{{ID: "r", Name: "SSH", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 22}}}
	name, st, _ = d.explain(policy.Contact{Direction: "in", Protocol: "tcp", RemoteIP: "1.1.1.1", LocalPort: 22, Host: "h"}, now)
	if name != "SSH" || st != "open" {
		t.Fatal(name, st)
	}
	if d.needsQuestion(policy.Contact{Direction: "in", Protocol: "tcp", RemoteIP: "1.1.1.1", LocalPort: 22, Host: "h"}, now) {
		t.Fatal("matching allow still asks")
	}
	name, st, _ = d.explain(policy.Contact{Direction: "bridge", RemoteIP: "172.17.0.3", Host: "h"}, now)
	if name != "docker" || st != "open" {
		t.Fatal("bridge", name, st)
	}
	name, st, _ = d.explain(policy.Contact{Direction: "tohost", Protocol: "tcp", RemoteIP: "172.17.0.1", RemotePort: 22, Host: "h"}, now)
	if name != "docker" || st != "open" {
		t.Fatal("tohost learn", name, st)
	}
	d.mode = "quarantine"
	name, st, _ = d.explain(policy.Contact{Direction: "tohost", Protocol: "tcp", RemoteIP: "172.17.0.1", RemotePort: 22, Host: "h"}, now)
	if name != "карантин" || st != "block" {
		t.Fatal("quarantine tohost", name, st)
	}
	name, st, _ = d.explain(policy.Contact{Direction: "tohost", Protocol: "udp", RemoteIP: "172.17.0.1", RemotePort: 53, Host: "h"}, now)
	if name != "docker" || st != "open" {
		t.Fatal("quarantine dns", name, st)
	}
	name, st, _ = d.explain(policy.Contact{Direction: "fromhost", Protocol: "tcp", RemoteIP: "172.17.0.2", RemotePort: 80, Host: "h"}, now)
	if name != "docker" || st != "open" {
		t.Fatal("fromhost", name, st)
	}
	d.mode = "learn"
	name, st, _ = d.explain(policy.Contact{RemoteIP: "9.9.9.9", Host: "h"}, now)
	if name != "обучение" || st != "block" {
		t.Fatal(name, st)
	}
	if !d.needsQuestion(policy.Contact{RemoteIP: "9.9.9.9", Host: "h"}, now) {
		t.Fatal("learn unmatched dropped the question")
	}
	d.mode = "allow"
	if d.needsQuestion(policy.Contact{RemoteIP: "9.9.9.9", Host: "h"}, now) {
		t.Fatal("allow mode asked")
	}
	d.mode = "block"
	name, st, _ = d.explain(policy.Contact{RemoteIP: "9.9.9.9", Host: "h"}, now)
	if name != "блокировать" || st != "block" || d.needsQuestion(policy.Contact{RemoteIP: "9.9.9.9", Host: "h"}, now) {
		t.Fatal(name, st)
	}
}
