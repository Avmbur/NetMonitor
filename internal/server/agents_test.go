package server

import (
	"errors"
	"net/http/httptest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"strings"
	"testing"
	"time"
)

func TestAgentLifecycleAndEmptyPark(t *testing.T) {
	s, cert := batchFixture(t)
	s.st.DB.Exec("UPDATE agents SET trust_state='pending'")
	before := s.uiState("", "settings")
	if before.err != nil || before.HasTrusted || len(before.Servers) != 0 || len(before.Agents) != 1 {
		t.Fatal(before.err, before)
	}
	if err := s.changeAgent("missing", "trust", "x", ""); !errors.Is(err, errAgentMissing) {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "trust", "Новое имя", ""); err != nil {
		t.Fatal(err)
	}
	after := s.uiState("", "settings")
	if !after.HasTrusted || after.Agents[0].Name != "Новое имя" {
		t.Fatal(after)
	}
	if err := s.changeAgent("a", "reject", "", ""); !errors.Is(err, errAgentState) {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "revoke", "", ""); err != nil {
		t.Fatal(err)
	}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 1}); code != 401 {
		t.Fatal("revoked credential accepted", code)
	}
	after = s.uiState("", "settings")
	if after.HasTrusted || len(after.Servers) != 0 || after.Agents[0].Trust != "revoked" {
		t.Fatal(after)
	}
	s.st.DB.Exec("UPDATE agents SET trust_state='pending'")
	if err := s.changeAgent("a", "reject", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAgentRemovesRow(t *testing.T) {
	s, cert := batchFixture(t)
	s.st.DB.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES('c1','a','ban','{}',1)`)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('fw_status:a','{}'),('inventory:h','{}'),('host_control:h','{}'),('monitor_host_id','h')`)
	if err := s.changeAgent("a", "delete", "", ""); err != nil {
		t.Fatal(err)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	if n != 0 {
		t.Fatal("agent remained", n)
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands`).Scan(&n)
	if n != 0 {
		t.Fatal("commands remained", n)
	}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 1}); code != 401 {
		t.Fatal("deleted credential accepted", code)
	}
	after := s.uiState("", "settings")
	if after.HasTrusted || len(after.Agents) != 0 || len(after.Servers) != 0 {
		t.Fatal(after)
	}
	var mon, ctrl string
	s.st.DB.QueryRow(`SELECT COALESCE((SELECT v FROM settings WHERE k='monitor_host_id'),'')`).Scan(&mon)
	if mon != "h" {
		t.Fatal("monitor_host_id", mon)
	}
	s.st.DB.QueryRow(`SELECT COALESCE((SELECT v FROM settings WHERE k='host_control:h'),'')`).Scan(&ctrl)
	if ctrl == "" {
		t.Fatal("host_control wiped")
	}
	if err := s.changeAgent("a", "delete", "", ""); !errors.Is(err, errAgentMissing) {
		t.Fatal(err)
	}
}

func TestRemoveAgentQueuesUntilAck(t *testing.T) {
	s, cert := batchFixture(t)
	if err := s.changeAgent("a", "remove", "", ""); !errors.Is(err, errAgentSilent) {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=?`, store.NowMS()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state='pending'`); err != nil {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "remove", "", ""); !errors.Is(err, errAgentState) {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state='trusted', policy_rev=2`); err != nil {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "remove", "", "10.0.0.8"); err != nil {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "remove", "", ""); err != nil {
		t.Fatal(err)
	}
	var n int
	var id, kind string
	if err := s.st.DB.QueryRow(`SELECT COUNT(*), MIN(command_id), MIN(kind) FROM commands`).Scan(&n, &id, &kind); err != nil {
		t.Fatal(err)
	}
	if n != 1 || kind != "uninstall" || id == "" {
		t.Fatal(n, id, kind)
	}
	if _, err := s.st.DB.Exec(`UPDATE commands SET delivered_at_ms=1, delivered_rev=2 WHERE command_id=?`, id); err != nil {
		t.Fatal(err)
	}
	rev := int64(2)
	// Старая сборка подтверждает uninstall в Ack, не умея его выполнить.
	st := &protocol.ApplyStatus{Backend: "nftables", DesiredRev: 2, AppliedRev: &rev, CommandIDs: []string{id}}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 2, Ack: []string{id}, Status: st}); code != 200 {
		t.Fatal(code)
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	if n != 1 {
		t.Fatal("old agent ack removed the row")
	}
	if ui := s.uiState("", "settings"); len(ui.Agents) != 1 || ui.Agents[0].Removing != "old" {
		t.Fatal(ui.Agents)
	}
	if err := s.changeAgent("a", "remove", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.st.DB.QueryRow(`SELECT command_id FROM commands WHERE acked_at_ms IS NULL`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if ui := s.uiState("", "settings"); ui.Agents[0].Removing != "wait" {
		t.Fatal(ui.Agents[0].Removing)
	}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 2, Uninstalled: id, Status: st}); code == 200 {
		t.Fatal("undelivered uninstall accepted")
	}
	if _, err := s.st.DB.Exec(`UPDATE commands SET delivered_at_ms=1, delivered_rev=2 WHERE command_id=?`, id); err != nil {
		t.Fatal(err)
	}
	// The previous pre-removal promise must neither forget the agent nor
	// let that build proceed to its unsafe cleanup.
	broken := &protocol.ApplyStatus{Backend: "nftables", DesiredRev: 2, Error: "nft: fail", CommandIDs: []string{id}}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 2, Uninstalled: id, Status: broken}); code != 409 {
		t.Fatal(code)
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	if n != 1 {
		t.Fatal("pre-removal promise deleted agent", n)
	}
	if ui := s.uiState("", "settings"); ui.Agents[0].Removing != "old" {
		t.Fatal(ui.Agents)
	}

}

func TestResumeHistoryOnTrust(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='box', last_seen_ms=? WHERE host_id='h'`, now)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('host_control:h','{"mode":"learn"}')`)
	s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('r-keep',1,1,?)`, `{"id":"r-keep","name":"ssh","action":"allow","hosts":["h"]}`)
	s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
		VALUES('oldflow','h','a','b',?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, now, now, now)
	if err := s.changeAgent("a", "delete", "", ""); err != nil {
		t.Fatal(err)
	}
	s.st.DB.Exec(`INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h2','box',?,?)`, now, now)
	s.st.DB.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,display_name,first_seen_ms) VALUES('a2','h2','fp2','pending','box',?)`, now)
	st := s.uiState("", "settings")
	var pending uiAgent
	for _, ag := range st.Agents {
		if ag.AgentID == "a2" {
			pending = ag
		}
	}
	if pending.ResumeHost != "h" || pending.ResumeName != "box" {
		t.Fatalf("resume hint %+v", pending)
	}
	if err := s.applyAgentChange("a2", "trust", "box", "", true); err != nil {
		t.Fatal(err)
	}
	var host string
	s.st.DB.QueryRow(`SELECT host_id FROM agents WHERE agent_id='a2'`).Scan(&host)
	if host != "h" {
		t.Fatal("host", host)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM hosts WHERE host_id='h2'`).Scan(&n)
	if n != 0 {
		t.Fatal("new host kept")
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM flows WHERE host_id='h' AND flow_uid='oldflow'`).Scan(&n)
	if n != 1 {
		t.Fatal("history lost")
	}
	var owner string
	s.st.DB.QueryRow(`SELECT agent_id FROM flows WHERE flow_uid='oldflow'`).Scan(&owner)
	if owner != "a2" {
		t.Fatal("flow owner", owner)
	}
	var ctrl, hosts string
	s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='host_control:h'`).Scan(&ctrl)
	if !strings.Contains(ctrl, "learn") {
		t.Fatal("mode lost", ctrl)
	}
	s.st.DB.QueryRow(`SELECT payload FROM policy_rules WHERE rule_id='r-keep'`).Scan(&hosts)
	if !strings.Contains(hosts, `"h"`) {
		t.Fatal("rule lost", hosts)
	}
	if err := s.applyAgentChange("a2", "trust", "box", "", true); !errors.Is(err, errAgentState) {
		t.Fatal(err)
	}
}

func TestResumeHistoryByIP(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='oldbox', last_seen_ms=? WHERE host_id='h'`, now)
	s.st.DB.Exec(`UPDATE agents SET last_src_ip='10.20.30.40' WHERE agent_id='a'`)
	if err := s.changeAgent("a", "delete", "", ""); err != nil {
		t.Fatal(err)
	}
	s.st.DB.Exec(`INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h3','newbox',?,?)`, now, now)
	s.st.DB.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,display_name,first_seen_ms,last_src_ip) VALUES('a3','h3','fp3','pending','newbox',?,'10.20.30.40')`, now)
	st := s.uiState("", "settings")
	var pending uiAgent
	for _, ag := range st.Agents {
		if ag.AgentID == "a3" {
			pending = ag
		}
	}
	if pending.ResumeHost != "h" {
		t.Fatalf("ip resume hint %+v", pending)
	}
	if err := s.applyAgentChange("a3", "trust", "newbox", "", true); err != nil {
		t.Fatal(err)
	}
	var host string
	s.st.DB.QueryRow(`SELECT host_id FROM agents WHERE agent_id='a3'`).Scan(&host)
	if host != "h" {
		t.Fatal("host", host)
	}
}
func TestAgentChangeRollsBackOnAuditFailure(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("UPDATE agents SET trust_state='pending'")
	s.st.DB.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'full'); END")
	if err := s.changeAgent("a", "trust", "name", ""); err == nil {
		t.Fatal("failure hidden")
	}
	var state string
	s.st.DB.QueryRow("SELECT trust_state FROM agents").Scan(&state)
	if state != "pending" {
		t.Fatal("partial trust")
	}
}
func TestUIReadFailureIsNotEmptySuccess(t *testing.T) {
	for _, table := range []string{"never_block", "ip_groups", "policy_rules", "learn_questions", "audit_log", "flows", "settings"} {
		t.Run(table, func(t *testing.T) {
			s, _ := batchFixture(t)
			if _, err := s.st.DB.Exec("ALTER TABLE " + table + " RENAME TO broken_" + table); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.handleState(w, httptest.NewRequest("GET", "/ui/api/state", nil))
			if w.Code != 500 {
				t.Fatal("broken query returned successful state", w.Code)
			}
		})
	}
}
func TestOpenPollSeesRevocation(t *testing.T) {
	s, cert := batchFixture(t)
	done := make(chan int, 1)
	go func() { done <- postPoll(t, s, cert, protocol.PollReq{Rev: 0}) }()
	time.Sleep(100 * time.Millisecond)
	if err := s.changeAgent("a", "revoke", "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(time.Second * 3):
		t.Fatal("long poll kept stale trust")
	}
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil || pr.Authorized || len(pr.Commands) > 0 {
		t.Fatal(pr, err)
	}
}
