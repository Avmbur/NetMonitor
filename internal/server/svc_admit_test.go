package server

import (
	"context"
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/svcnet"
)

func TestUpdateRuleLimitsHTTPSToGitHub(t *testing.T) {
	s, _ := batchFixture(t)
	// Правило прежней сборки: 443 на любой адрес.
	old := updateRule()
	old.Match.OnDemand = nil
	old.Name = "служебные · обновления (руками не трогать)"
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := upsertMonitorRule(tx, old, 1); return err }); err != nil {
		t.Fatal(err)
	}
	var rev int64
	s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev)
	if err := s.ensureUpdateRule(); err != nil {
		t.Fatal(err)
	}
	var again int64
	s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&again)
	if again == rev {
		t.Fatal("upgraded rule not delivered to agents")
	}
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pr.Rules {
		if r.ID != parkRuleUpdate {
			continue
		}
		if r.Match.Networks != nil || len(r.Match.OnDemand) != len(svcnet.UpdateHosts) || r.Match.OnDemand[0] != "api.github.com" {
			t.Fatalf("rule is not limited to GitHub: %+v", r.Match)
		}
		c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, Cgroup: "system.slice/nmagent.service"}
		if r.Match.Matches(c) {
			t.Fatal("any HTTPS address still matches the service rule")
		}
		return
	}
	t.Fatal("update rule missing from the snapshot")
}

func TestAdmitOnMonitorWaitsForAgent(t *testing.T) {
	s, _ := batchFixture(t)
	oldWait := admitWait
	t.Cleanup(func() { admitWait = oldWait })
	admitWait = 300 * time.Millisecond
	ips := []netip.Addr{netip.MustParseAddr("140.82.121.6")}
	count := func() int {
		var n int
		s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE kind=?`, svcnet.AdmitKind).Scan(&n)
		return n
	}
	// Агент не на этой машине: просить некого, фильтра монитора он не держит.
	if err := s.admitOnMonitor(context.Background(), ips); err != nil || count() != 0 {
		t.Fatal("asked a foreign agent", err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('monitor_host_id','h')`); err != nil {
		t.Fatal(err)
	}
	if err := s.admitOnMonitor(context.Background(), ips); err == nil {
		t.Fatal("connected without the agent confirming the address")
	}
	// Агент забирает команду обычным опросом и подтверждает её.
	admitWait = 3 * time.Second
	done := make(chan error, 1)
	go func() { done <- s.admitOnMonitor(context.Background(), ips) }()
	var cmd protocol.Command
	var rev int64
	for deadline := time.Now().Add(2 * time.Second); cmd.ID == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		pr, err := s.pollSnapshot("a", "trusted", 0)
		if err != nil {
			t.Fatal(err)
		}
		rev = pr.PolicyRev
		for _, c := range pr.Commands {
			if c.Kind == svcnet.AdmitKind && c.ID != "" {
				if got, _, err := svcnet.ParsePayload(c.Payload); err == nil && got[0] == ips[0] {
					cmd = c
				}
			}
		}
	}
	if cmd.ID == "" {
		t.Fatal("command not delivered")
	}
	var ids []string
	pr, _ := s.pollSnapshot("a", "trusted", rev)
	for _, c := range pr.Commands {
		ids = append(ids, c.ID)
	}
	st := protocol.ApplyStatus{Backend: "nftables", DesiredRev: rev, AppliedRev: &rev, CommandIDs: ids}
	if err := s.recordApply("a", protocol.PollReq{Rev: rev, Ack: ids, Status: &st}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Подтверждённые и невыданные просьбы старше минуты не копятся.
	if _, err := s.st.DB.Exec(`UPDATE commands SET created_at_ms=created_at_ms-120000 WHERE kind=?`, svcnet.AdmitKind); err != nil {
		t.Fatal(err)
	}
	admitWait = 50 * time.Millisecond
	_ = s.admitOnMonitor(context.Background(), ips)
	if n := count(); n != 1 {
		t.Fatalf("%d admit commands kept", n)
	}
}
