package agent

import (
	"net/netip"
	pol "netmonitor/internal/policy"
	"reflect"
	"testing"
)

func TestPreciseSnapshotRetainsAllConditionsAndQuarantine(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	pr := policy(5)
	pr.Model = 1
	pr.Mode = "quarantine"
	pr.Rules = []pol.Rule{{ID: "precise", Enabled: true, Version: 2, Action: "allow", Order: 5, Hosts: []string{"h1"}, Except: []string{"h2"}, FromMS: 1000, UntilMS: 9999999999999, Match: pol.Match{Direction: "out", Protocol: "tcp", RemotePort: 443, Networks: []string{"192.0.2.0/24"}}}}
	pr.Groups = []pol.Rule{{ID: "empty", Enabled: true, Action: "deny", Match: pol.Match{Networks: []string{}}}}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	before := a.policyLocked()
	restart := &Agent{st: a.st, cfg: a.cfg, firewall: f}
	if err := restart.loadLocalFW(); err != nil {
		t.Fatal(err)
	}
	if after := restart.policyLocked(); !reflect.DeepEqual(before, after) {
		t.Fatalf("before=%+v after=%+v", before, after)
	}
}

func TestOnceLocalSpendSurvivesPollAndRestart(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	a.hostID = "h"
	pr := policy(3)
	pr.Model = 1
	pr.Mode = "learn"
	pr.Rules = []pol.Rule{{ID: "o1", Enabled: true, Action: "allow", Once: true, Match: pol.Match{Direction: "out", Protocol: "tcp", RemotePort: 80, Networks: []string{"198.18.0.2/32"}}}}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	unlock, err := a.lockFirewall()
	if err != nil {
		t.Fatal(err)
	}
	if err = a.consumeOnceLocked("o1"); err != nil {
		unlock()
		t.Fatal(err)
	}
	unlock()
	if !f.policy.Rules[0].OnceUsed {
		t.Fatal("kernel still has the once allow")
	}
	pr.PolicyRev = 4
	if err = a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if !f.policy.Rules[0].OnceUsed {
		t.Fatal("poll rearmed once")
	}
	restart := &Agent{st: a.st, cfg: a.cfg, firewall: f}
	if err = restart.loadLocalFW(); err != nil {
		t.Fatal(err)
	}
	if !restart.policyLocked().Rules[0].OnceUsed {
		t.Fatal("restart rearmed once")
	}
}

func TestStarterSSHOpensLocalSSHDPorts(t *testing.T) {
	old := localSSHPorts
	localSSHPorts = func() []int { return []int{2222} }
	defer func() { localSSHPorts = old }()
	pr := policy(1)
	pr.Rules = []pol.Rule{{ID: pol.StarterSSH, Enabled: true, Action: "allow", Match: pol.Match{Direction: "in", Protocol: "tcp", LocalPort: 22}}}
	p, err := policyFromPoll(pr, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 || p.Rules[1].Match.LocalPort != 2222 {
		t.Fatal("sshd port not opened before the monitor has the report", p.Rules)
	}
}
