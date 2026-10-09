package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
	"time"
)

func TestReviewServiceSSHStartsEmpty(t *testing.T) {
	s, cert := batchFixture(t)
	if code, _ := sendBatch(t, s, cert, sshEv("old", 1, store.NowMS(), store.NowMS(), "203.0.113.50")); code != 200 {
		t.Fatal(code)
	}
	fresh := &Server{st: s.st}
	if err := fresh.ensureSSH(); err != nil {
		t.Fatal(err)
	}
	if n := len(fresh.ssh.committed()); n != 0 {
		t.Fatalf("restored %d old SSH hits", n)
	}
}

func TestReviewServiceReplayDoesNotRepeatAudit(t *testing.T) {
	s, send := serviceFixture(t)
	ev := healthEv("restore", 1, protocol.HealthPayload{Kind: "firewall_restored"})
	for i := 0; i < 3; i++ {
		if code, _ := send(ev); code != 200 {
			t.Fatal(code)
		}
	}
	if n := countTable(t, s, "audit_log"); n != 1 {
		t.Fatalf("replayed audit %d times", n)
	}
}

func TestReviewServiceCoveredQuestionRetry(t *testing.T) {
	s, send := serviceFixture(t)
	r := policy.Rule{ID: "allow", Version: 1, Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 443}}
	raw, _ := json.Marshal(r)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('allow',1,1,?)", string(raw))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, DedupKey: "q"})
	ev := protocol.Event{EventID: "q", Seq: 1, Kind: "question", ObservedAtMS: store.NowMS(), Payload: payload}
	for i := 0; i < 3; i++ {
		if code, _ := send(ev); code != 200 {
			t.Fatal(code)
		}
	}
	ev.EventID = "another-delivery"
	ev.Seq = 2
	if code, _ := send(ev); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "learn_questions"); n != 1 {
		t.Fatalf("retry created %d questions", n)
	}
}

func reviewPost(t *testing.T, s *Server, cert *x509.Certificate, b protocol.Batch) (int, protocol.Ack) {
	t.Helper()
	raw, _ := json.Marshal(b)
	r := httptest.NewRequest("POST", "/v1/batch", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	var ack protocol.Ack
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("%d %s: %v", w.Code, w.Body.String(), err)
	}
	return w.Code, ack
}

func TestReviewServiceAgentRestart(t *testing.T) {
	s, cert := batchFixture(t)

	s.session = "monitor"
	if _, err := s.registerStream("a", "first"); err != nil {
		t.Fatal(err)
	}
	post := func(instance string, ev ...protocol.Event) int {
		code, _ := reviewPost(t, s, cert, protocol.Batch{Session: s.session, Instance: instance, Events: ev})
		return code
	}
	if code := post("first", flowEvent("open", 900, openFlow("same-uid"))); code != 200 {
		t.Fatal(code)
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 1 {
		t.Fatal(n)
	}
	if _, err := s.registerStream("a", "second"); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 0 {
		t.Fatalf("old process left %d ghosts", n)
	}
	if code := post("first", flowEvent("late", 901, openFlow("ghost"))); code != 409 {
		t.Fatalf("old process accepted %d", code)
	}
	if code := post("second", flowEvent("new", 1, openFlow("same-uid"))); code != 200 {
		t.Fatal(code)
	}
	p := openFlow("same-uid")
	now := store.NowMS()
	p.EndedAtMS = &now
	if code := post("second", flowEvent("close", 2, p)); code != 200 {
		t.Fatal(code)
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 0 {
		t.Fatalf("low seq closure ignored: %d", n)
	}
	// A third process can describe a current connection even with a reused UID.
	if _, err := s.registerStream("a", "third"); err != nil {
		t.Fatal(err)
	}
	if code := post("third", flowEvent("again", 1, openFlow("same-uid"))); code != 200 {
		t.Fatal(code)
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 1 {
		t.Fatalf("old tombstone hid new process: %d", n)
	}
}

func TestReviewServiceRequiresSession(t *testing.T) {
	s, cert := batchFixture(t)

	s.session = "monitor"
	for _, session := range []string{"", "old"} {
		code, ack := reviewPost(t, s, cert, protocol.Batch{Session: session, Events: []protocol.Event{flowEvent("old", 1, openFlow("ghost"))}})
		if code != 409 || len(ack.Ack) != 0 || ack.Session != s.session {
			t.Fatalf("%d %+v", code, ack)
		}
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 0 {
		t.Fatal(n)
	}
}

func TestReviewServiceLateFlowAfterClosedRetention(t *testing.T) {
	s, cert := batchFixture(t)

	s.session = "monitor"
	if _, err := s.registerStream("a", "first"); err != nil {
		t.Fatal(err)
	}
	p := openFlow("closed")
	now := store.NowMS()
	p.EndedAtMS = &now
	if code, _ := reviewPost(t, s, cert, protocol.Batch{Session: s.session, Instance: "first", Lane: "urgent", Events: []protocol.Event{flowEvent("close", 1, p)}}); code != 200 {
		t.Fatal(code)
	}
	s.live.mu.Lock()
	s.live.rotateClosedLocked(true)
	s.live.rotateClosedLocked(true)
	s.live.mu.Unlock()
	late := flowEvent("late", 2, openFlow("closed"))
	late.ObservedAtMS = now - int64((31*time.Minute)/time.Millisecond)
	if code, _ := reviewPost(t, s, cert, protocol.Batch{Session: s.session, Instance: "first", Lane: "history", Events: []protocol.Event{late}}); code != 200 {
		t.Fatal(code)
	}
	if n, _, _, _ := s.liveActivity("", false, false); n != 0 {
		t.Fatalf("late replay resurrected %d flows", n)
	}
}

func TestReviewServiceRollbackKeepsPulseAndReplayClean(t *testing.T) {
	s, send := serviceFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, e := tx.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fail'); END")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	alive := healthEv("alive", 1, protocol.HealthPayload{Kind: "alive", BootID: "b1"})
	restored := healthEv("restored", 2, protocol.HealthPayload{Kind: "firewall_restored"})
	if code, _ := send(alive, restored); code != 500 {
		t.Fatalf("want failed batch, got %d", code)
	}
	if len(s.hostSeen) != 0 || len(s.hostInv) != 0 {
		t.Fatal("failed batch published pulse")
	}
	if err := s.st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("DROP TRIGGER fail_audit"); return e }); err != nil {
		t.Fatal(err)
	}
	if code, _ := send(alive, restored); code != 200 {
		t.Fatal(code)
	}
	if s.hostSeen["h"] == 0 || countTable(t, s, "audit_log") != 1 {
		t.Fatal("failed batch was acknowledged as replay")
	}
}

func TestReviewServiceSSHRetryDoesNotUndoRemoval(t *testing.T) {
	s, send := serviceFixture(t)
	events := sshBurst("new", "203.0.113.50", 5, store.NowMS())
	if code, _ := send(events...); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "blocks"); n != 1 {
		t.Fatal(n)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("UPDATE blocks SET state='removed'"); return e }); err != nil {
		t.Fatal(err)
	}
	if code, _ := send(events...); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "blocks"); n != 1 {
		t.Fatalf("replay re-banned address: %d", n)
	}
}

func TestReviewServiceLivePulseIsCurrent(t *testing.T) {
	s, send := serviceFixture(t)
	if code, _ := send(healthEv("alive", 1, protocol.HealthPayload{Kind: "alive", BootID: "b1"}), flowEvent("open", 2, openFlow("current"))); code != 200 {
		t.Fatal(code)
	}
	n, rows, _, err := s.liveActivity("", false, true)
	if err != nil || n != 1 || rows[0].last < store.NowMS()-60000 {
		t.Fatalf("live host shown stale: %d %+v %v", n, rows, err)
	}
}
func TestReviewServiceDNSIsMemoryOnly(t *testing.T) {
	s, send := serviceFixture(t)
	raw, _ := json.Marshal(protocol.DNSPayload{Name: "fresh.example.org", IP: "203.0.113.20", Kind: "a"})
	if code, _ := send(protocol.Event{EventID: "dns", Seq: 1, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: raw}); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "dns_seen"); n != 0 {
		t.Fatalf("ordinary DNS on disk %d", n)
	}
	if name := s.lookupDNS(nil, "h", "203.0.113.20", "tcp", 443); name != "fresh.example.org" {
		t.Fatal(name)
	}
	for i := 0; i < liveNameLimit+5; i++ {
		raw, _ = json.Marshal(protocol.DNSPayload{Name: "name", IP: fmt.Sprintf("10.1.%d.%d", i/256, i%256)})
		s.noteLiveDNS("h", protocol.Event{Payload: raw}, int64(i))
	}
	if n := len(s.liveNames); n > liveNameLimit {
		t.Fatalf("unbounded names %d", n)
	}
}
