package server

import (
	"database/sql"
	"testing"

	"netmonitor/internal/policy"
	"netmonitor/internal/store"
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

func TestQuarantineKeepsUnansweredLearnQuestions(t *testing.T) {
	s, _ := batchFixture(t)
	setHostControl(t, s, `{"mode":"learn","quarantine":true}`)
	if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('host_storm:h','9000000000000')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms)
		VALUES('b','all','198.18.0.2',zeroblob(16),'both','active','тест','manual','test',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('r-allow',1,1,?)`,
		`{"id":"r-allow","name":"dns","enabled":true,"action":"allow","match":{"direction":"out","protocol":"tcp","networks":["1.1.1.1/32"],"remote_port":443}}`); err != nil {
		t.Fatal(err)
	}
	groupReq(t, s, `{"name":"сигнал","policy":"alert","members":"203.0.113.8","hosts":["h"]}`, 200)
	insertOpenQuestion(t, s, "q-open", "in", "9.9.9.9", 443)
	insertOpenQuestion(t, s, "q-ban", "out", "198.18.0.2", 80)
	insertOpenQuestion(t, s, "q-allow", "out", "1.1.1.1", 443)
	insertOpenQuestion(t, s, "q-alert", "out", "203.0.113.8", 80)
	if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status,answer)
		VALUES('q-old','h','q-old',1,1,1,'out','tcp','203.0.113.9',9,'answered','deny')`); err != nil {
		t.Fatal(err)
	}
	closeHostQuestions(t, s)
	questionIs(t, s, "q-open", "open", "")
	questionIs(t, s, "q-ban", "answered", "deny")
	questionIs(t, s, "q-allow", "answered", "allow")
	questionIs(t, s, "q-alert", "open", "")
	questionIs(t, s, "q-old", "answered", "deny")

	setHostControl(t, s, `{"mode":"block","quarantine":true}`)
	closeHostQuestions(t, s)
	questionIs(t, s, "q-open", "answered", "deny")
	questionIs(t, s, "q-alert", "open", "")

	setHostControl(t, s, `{"mode":"park","quarantine":true}`)
	if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('park_mode','block')`); err != nil {
		t.Fatal(err)
	}
	insertOpenQuestion(t, s, "q-park-block", "out", "8.8.4.4", 53)
	closeHostQuestions(t, s)
	questionIs(t, s, "q-park-block", "answered", "deny")

	if _, err := s.st.DB.Exec(`UPDATE settings SET v='learn' WHERE k='park_mode'`); err != nil {
		t.Fatal(err)
	}
	insertOpenQuestion(t, s, "q-park-learn", "out", "6.6.6.6", 53)
	closeHostQuestions(t, s)
	questionIs(t, s, "q-park-learn", "open", "")
	questionIs(t, s, "q-park-block", "answered", "deny")
	questionIs(t, s, "q-old", "answered", "deny")
}

func setHostControl(t *testing.T, s *Server, raw string) {
	t.Helper()
	if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('host_control:h',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, raw); err != nil {
		t.Fatal(err)
	}
}

func insertOpenQuestion(t *testing.T, s *Server, id, dir, ip string, port int) {
	t.Helper()
	_, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
		VALUES(?,?,?,1,1,1,?,?,?,?,'open')`, id, "h", id, dir, "tcp", ip, port)
	if err != nil {
		t.Fatal(err)
	}
}

func closeHostQuestions(t *testing.T, s *Server) {
	t.Helper()
	if err := s.st.Update(func(tx *sql.Tx) error {
		return closeCoveredQuestions(tx, "h", store.NowMS())
	}); err != nil {
		t.Fatal(err)
	}
}

func questionIs(t *testing.T, s *Server, id, status, answer string) {
	t.Helper()
	var gotStatus, gotAnswer string
	if err := s.st.DB.QueryRow(`SELECT status, COALESCE(answer,'') FROM learn_questions WHERE question_id=?`, id).Scan(&gotStatus, &gotAnswer); err != nil {
		t.Fatal(id, err)
	}
	if gotStatus != status || gotAnswer != answer {
		t.Fatalf("%s: %s/%s, want %s/%s", id, gotStatus, gotAnswer, status, answer)
	}
}
