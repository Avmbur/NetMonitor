package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func reviewQuestion(id string, seq int64, repeats int) protocol.Event {
	raw, _ := json.Marshal(protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, DedupKey: "review", Repeats: repeats})
	return protocol.Event{EventID: id, Seq: seq, Kind: "question", ObservedAtMS: store.NowMS(), Payload: raw}
}

func TestReviewQuestionRetryAndRollback(t *testing.T) {
	s, send := serviceFixture(t)
	for _, e := range []protocol.Event{reviewQuestion("one", 1, 1), reviewQuestion("two", 2, 3), reviewQuestion("two", 2, 3)} {
		code, ack := send(e)
		if code != 200 || ack.Error != "" {
			t.Fatalf("send %d %+v", code, ack)
		}
	}
	aborted := errors.New("abort after flush")
	if err := s.st.Update(func(tx *sql.Tx) error {
		if err := s.flushQuestionRepeats(tx, store.NowMS()); err != nil {
			return err
		}
		return aborted
	}); !errors.Is(err, aborted) {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { return s.flushQuestionRepeats(tx, store.NowMS()) }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT repeats FROM learn_questions WHERE dedup_key='review'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("repeats=%d, want 4 after retry and failed flush", n)
	}
}

func TestReviewCollectionFaultPublication(t *testing.T) {
	s, send := serviceFixture(t)
	if code, _ := send(healthEv("restored", 1, protocol.HealthPayload{Kind: "firewall_restored"})); code != 200 {
		t.Fatal(code)
	}
	if got := s.collectFault["h"]; got != "" {
		t.Fatalf("normal health shown as fault: %s", got)
	}
	aborted := errors.New("abort")
	err := s.st.Update(func(tx *sql.Tx) error {
		_, err := s.noteHealth(tx, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, healthEv("fail", 2, protocol.HealthPayload{Kind: "dump_error", Note: "failed"}), store.NowMS())
		if err != nil {
			return err
		}
		return aborted
	})
	if !errors.Is(err, aborted) {
		t.Fatal(err)
	}
	if got := s.collectFault["h"]; got != "" {
		t.Fatalf("rolled back fault published: %s", got)
	}
	if code, _ := send(healthEv("real", 3, protocol.HealthPayload{Kind: "dump_error", Note: "failed"})); code != 200 {
		t.Fatal(code)
	}
	if got := s.collectFault["h"]; got == "" {
		t.Fatal("real fault missing")
	}
}

func TestReviewSSHBruteCount(t *testing.T) {
	s, _ := serviceFixture(t)
	now := store.NowMS()
	if err := s.ensureSSH(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		at := now - 120000 + int64(i)*1000
		if i == 8 {
			at = now
		}
		raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.20", ObservedAtMS: at})
		ev := protocol.Event{EventID: fmt.Sprint("ssh", i), Kind: "ssh", Seq: int64(i + 1), ObservedAtMS: at, Payload: raw}
		job := &batchJob{}
		err := s.st.Update(func(tx *sql.Tx) error {
			if err := s.noteSSH(job, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, ev); err != nil {
				return err
			}
			return s.persistSSHBrute(tx, "h", ev, at)
		})
		if err != nil {
			s.ssh.drop(job)
			t.Fatal(err)
		}
		s.ssh.keep(job)
	}
	var n int
	var first, last int64
	if err := s.st.DB.QueryRow("SELECT attempts,first_at_ms,last_at_ms FROM ssh_brute WHERE host_id='h'").Scan(&n, &first, &last); err != nil {
		t.Fatal(err)
	}
	if n != 9 || first != now-120000 || last != now {
		t.Fatalf("brute count=%d first=%d last=%d; want 9 %d %d", n, first, last, now-120000, now)
	}
}

func TestReviewQuestionAnswerSavesRepeats(t *testing.T) {
	s, send := serviceFixture(t)
	send(reviewQuestion("q1", 1, 1))
	send(reviewQuestion("q2", 2, 3))
	var id string
	if err := s.st.DB.QueryRow("SELECT question_id FROM learn_questions").Scan(&id); err != nil {
		t.Fatal(err)
	}
	st := s.uiState("", "rules")
	found := false
	for _, q := range st.Questions {
		if q.ID == id {
			found = true
			if q.Repeats != 4 {
				t.Fatalf("visible repeats %d", q.Repeats)
			}
		}
	}
	if !found {
		t.Fatal("question missing")
	}
	raw, _ := json.Marshal(map[string]string{"id": id, "op": "dismiss"})
	w := httptest.NewRecorder()
	s.handleQuestion(w, httptest.NewRequest(http.MethodPost, "/ui/api/question", bytes.NewReader(raw)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var repeats int
	var status string
	if err := s.st.DB.QueryRow("SELECT repeats,status FROM learn_questions").Scan(&repeats, &status); err != nil {
		t.Fatal(err)
	}
	if repeats != 4 || status != "answered" {
		t.Fatalf("%d %s", repeats, status)
	}
}

func TestReviewDurableFloorAndNoTelemetryWrites(t *testing.T) {
	s, cert := batchFixture(t)

	s.session = "review-session"
	if _, err := s.registerStream("a", "review-process"); err != nil {
		t.Fatal(err)
	}
	send := func(floor int64, evs ...protocol.Event) protocol.Ack {
		t.Helper()
		body, _ := json.Marshal(protocol.Batch{Session: s.session, Instance: "review-process", QuestionPendingFrom: &floor, Events: evs})
		req := httptest.NewRequest("POST", "/v1/batch", bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		w := httptest.NewRecorder()
		s.handleBatch(w, req)
		var ack protocol.Ack
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ack) != nil || ack.Error != "" {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return ack
	}
	q := reviewQuestion("question", 1, 1)
	send(1, q)
	if countTable(t, s, "ingest_events") != 1 {
		t.Fatal("missing initial receipt")
	}
	send(2)
	if countTable(t, s, "ingest_events") != 0 {
		t.Fatal("receipt retained")
	}
	send(1, q)
	if countTable(t, s, "learn_questions") != 1 {
		t.Fatal("old request reapplied")
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TRIGGER review_no_agent_write BEFORE UPDATE ON agents BEGIN SELECT RAISE(ABORT,'telemetry writes agent'); END")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Old protocol fields must not cause disk writes in the service-only receiver.
	pending, assigned := int64(1), int64(100)
	raw, _ := json.Marshal(protocol.Batch{Session: s.session, Instance: "review-process", PendingFrom: &pending, AssignedThrough: &assigned, Events: []protocol.Event{flowEvent("newflow", 100, openFlow("live"))}})
	req := httptest.NewRequest("POST", "/v1/batch", bytes.NewReader(raw))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, req)
	if w.Code != 200 {
		t.Fatalf("telemetry rewrote agent: %d %s", w.Code, w.Body.String())
	}
}

func TestReviewSSHOneWritePerBurst(t *testing.T) {
	s, _ := serviceFixture(t)
	now := store.NowMS()
	j := &batchJob{}
	if err := s.ensureSSH(); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		for i := 0; i < 9; i++ {
			at := now - 120000 + int64(i)
			raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.40", ObservedAtMS: at})
			ev := protocol.Event{EventID: fmt.Sprintf("burst%d", i), Kind: "ssh", ObservedAtMS: at, Payload: raw}
			if err := s.noteSSH(j, ingest.Agent{HostID: "h"}, ev); err != nil {
				return err
			}
			if err := s.persistSSHBrute(tx, "h", ev, now, j); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.ssh.keep(j)
	var n int
	if err := s.st.DB.QueryRow("SELECT attempts FROM ssh_brute").Scan(&n); err != nil || n != 5 {
		t.Fatal("first threshold", n, err)
	}
	if err := s.flushSSHBrute(now + 30000); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow("SELECT attempts FROM ssh_brute").Scan(&n)
	if n != 5 {
		t.Fatal("rewritten before minute", n)
	}
	if err := s.flushSSHBrute(now + 60000); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow("SELECT attempts FROM ssh_brute").Scan(&n)
	if n != 9 {
		t.Fatal("lost or counted twice", n)
	}
	if err := s.flushSSHBrute(now + 120000); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow("SELECT attempts FROM ssh_brute").Scan(&n)
	if n != 9 {
		t.Fatal("quiet burst counted twice", n)
	}
}
