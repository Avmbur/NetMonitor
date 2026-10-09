package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func postLane(t *testing.T, s *Server, cert *x509.Certificate, lane string, events ...protocol.Event) (int, protocol.Ack) {
	t.Helper()
	code, ack, err := postLaneErr(s, cert, lane, events...)
	if err != nil {
		t.Fatal(err)
	}
	return code, ack
}

func postLaneErr(s *Server, cert *x509.Certificate, lane string, events ...protocol.Event) (int, protocol.Ack, error) {
	body, err := json.Marshal(protocol.Batch{Session: s.session, Instance: "test-process", Lane: lane, Events: events})
	if err != nil {
		return 0, protocol.Ack{}, err
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	var ack protocol.Ack
	if w.Code == 200 || w.Code == 409 {
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			return w.Code, protocol.Ack{}, err
		}
	}
	return w.Code, ack, nil
}

func ingestCount(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM ingest_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type laneResult struct {
	code int
	ack  protocol.Ack
	err  error
}

func TestHistoryBatchesShareOneCommit(t *testing.T) {
	s, cert := batchFixture(t)
	s.batchWait = 200 * time.Millisecond
	out := make(chan laneResult, 2)
	go func() {
		code, ack, err := postLaneErr(s, cert, "history", coalesceEvent("h1", 1))
		out <- laneResult{code, ack, err}
	}()
	time.Sleep(20 * time.Millisecond)
	go func() {
		code, ack, err := postLaneErr(s, cert, "heartbeat", coalesceEvent("h2", 2))
		out <- laneResult{code, ack, err}
	}()
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case r := <-out:
			if r.err != nil {
				t.Fatal(r.err)
			}
			if r.code != 200 || len(r.ack.Ack) != 1 {
				t.Fatalf("ack %+v", r)
			}
			got[r.ack.Ack[0]] = true
		case <-time.After(2 * time.Second):
			t.Fatal("batch did not finish")
		}
	}
	if !got["h1"] || !got["h2"] {
		t.Fatalf("acks %v", got)
	}
	if n := s.gate.commits.Load(); n != 1 {
		t.Fatalf("commits %d", n)
	}
	if ingestCount(t, s) != 2 {
		t.Fatalf("events %d", ingestCount(t, s))
	}
}

func TestUrgentDoesNotWaitForHistory(t *testing.T) {
	s, cert := batchFixture(t)
	s.batchWait = 500 * time.Millisecond
	started := time.Now()
	hist := make(chan laneResult, 1)
	go func() {
		code, ack, err := postLaneErr(s, cert, "history", coalesceEvent("slow", 1))
		hist <- laneResult{code, ack, err}
	}()
	time.Sleep(30 * time.Millisecond)
	code, ack := postLane(t, s, cert, "urgent", coalesceEvent("fast", 2))
	if time.Since(started) > 300*time.Millisecond {
		t.Fatalf("urgent waited %s", time.Since(started))
	}
	if code != 200 || len(ack.Ack) != 1 || ack.Ack[0] != "fast" {
		t.Fatalf("urgent %d %+v", code, ack)
	}
	select {
	case c := <-hist:
		if c.err != nil {
			t.Fatal(c.err)
		}
		if c.code != 200 {
			t.Fatalf("history %d %+v", c.code, c.ack)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("history did not finish")
	}
	if n := s.gate.commits.Load(); n != 1 {
		t.Fatalf("commits %d", n)
	}
}

func TestTelemetryWaitsToCommitAndKeepsControl(t *testing.T) {
	s, cert := batchFixture(t)
	s.batchWait = 250 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		code, ack, err := postLaneErr(s, cert, "history", coalesceEvent("later", 1))
		if err == nil && (code != 200 || len(ack.Ack) != 1) {
			err = errStatus{code, ack}
		}
		done <- err
	}()
	time.Sleep(40 * time.Millisecond)
	if ingestCount(t, s) != 0 {
		t.Fatal("event visible before commit")
	}
	mark := time.Now()
	err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO settings(k,v) VALUES('coalesce_probe','1')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(mark) > 150*time.Millisecond {
		t.Fatalf("control waited %s", time.Since(mark))
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not finish")
	}
	if ingestCount(t, s) != 1 {
		t.Fatalf("events %d", ingestCount(t, s))
	}
}

type errStatus struct {
	code int
	ack  protocol.Ack
}

func (e errStatus) Error() string {
	return "history batch was not acknowledged"
}

func TestCoalescedFailureDoesNotAck(t *testing.T) {
	s, cert := batchFixture(t)
	s.batchWait = 250 * time.Millisecond
	out := make(chan laneResult, 1)
	go func() {
		code, ack, err := postLaneErr(s, cert, "history", coalesceEvent("lose", 1))
		out <- laneResult{code, ack, err}
	}()
	time.Sleep(40 * time.Millisecond)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE agents SET trust_state='revoked' WHERE agent_id='a'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var got laneResult
	select {
	case got = <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("batch did not finish")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.code != http.StatusInternalServerError || len(got.ack.Ack) != 0 {
		t.Fatalf("acked a rolled back batch: %d %+v", got.code, got.ack)
	}
	if ingestCount(t, s) != 0 {
		t.Fatal("rolled back event stayed")
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE agents SET trust_state='trusted' WHERE agent_id='a'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.batchWait = 0
	code, ack := postLane(t, s, cert, "history", coalesceEvent("lose", 1))
	if code != 200 || len(ack.Ack) != 1 || ack.Ack[0] != "lose" {
		t.Fatalf("retry %d %+v", code, ack)
	}
	if ingestCount(t, s) != 1 {
		t.Fatalf("retry events %d", ingestCount(t, s))
	}
}

// Битая пачка одного агента в общем коммите откатывается одна: соседи
// записаны и подтверждены.
func TestCoalescedBadBatchDoesNotSinkNeighbours(t *testing.T) {
	s, cert := batchFixture(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	ag, err := s.agentFromTLS(r)
	if err != nil {
		t.Fatal(err)
	}
	ag.DeliveryLane = "history"
	ghost := ag
	ghost.ID = "ghost"
	now := store.NowMS()
	bad := &batchJob{ag: ghost, batch: protocol.Batch{Session: s.session, Instance: "test-process", Lane: "history", Events: []protocol.Event{coalesceEvent("bad", 1)}}, now: now, done: make(chan struct{})}
	good := &batchJob{ag: ag, batch: protocol.Batch{Session: s.session, Instance: "test-process", Lane: "history", Events: []protocol.Event{coalesceEvent("good", 2)}}, now: now, done: make(chan struct{})}
	s.batchGate().commit([]*batchJob{bad, good})
	if bad.err == nil || len(bad.res.Ack) != 0 {
		t.Fatalf("bad batch %+v %v", bad.res, bad.err)
	}
	if good.err != nil || len(good.res.Ack) != 1 || good.res.Ack[0] != "good" {
		t.Fatalf("good batch %+v %v", good.res, good.err)
	}
	if n := ingestCount(t, s); n != 1 {
		t.Fatalf("events %d", n)
	}
}

func TestFullHistoryBatchDoesNotWait(t *testing.T) {
	events := make([]protocol.Event, telemetryBatchFull)
	if !batchImmediate(protocol.Batch{Lane: "history", Events: events}) {
		t.Fatal("full backlog batch waits")
	}
	if batchImmediate(protocol.Batch{Lane: "history", Events: events[:1]}) {
		t.Fatal("small history batch is immediate")
	}
}

func coalescedJob(t *testing.T, s *Server, cert *x509.Certificate, id string, seq int64) *batchJob {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	ag, err := s.agentFromTLS(r)
	if err != nil {
		t.Fatal(err)
	}
	ag.DeliveryLane = "history"
	return &batchJob{ag: ag, batch: protocol.Batch{Session: s.session, Instance: "test-process", Lane: "history", Events: []protocol.Event{coalesceEvent(id, seq)}}, now: store.NowMS(), done: make(chan struct{})}
}

func TestTelemetryWaitIncludesPreviousCommit(t *testing.T) {
	s, cert := batchFixture(t)
	s.batchWait = 400 * time.Millisecond
	first := coalescedJob(t, s, cert, "first", 1)
	first.immediate = true
	second := coalescedJob(t, s, cert, "second", 2)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- s.st.Update(func(tx *sql.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	s.enqueueBatch(first)
	until := time.Now().Add(2 * time.Second)
	for s.batchGate().commits.Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("first batch did not reach writer")
		}
		time.Sleep(time.Millisecond)
	}
	s.enqueueBatch(second)
	time.Sleep(s.batchWait + 100*time.Millisecond)
	unblock()
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.done:
	case <-time.After(s.batchWait / 2):
		// Drain before fixture cleanup; the failure must not strand a writer.
		<-second.done
		t.Fatal("telemetry waited a fresh interval after the previous commit")
	}
	<-first.done
	for _, j := range []*batchJob{first, second} {
		if j.err != nil || len(j.res.Ack) != 1 {
			t.Fatalf("batch result %+v: %v", j.res, j.err)
		}
	}
}

func TestCoalescedRollbackAfterWritesAndAtCommit(t *testing.T) {
	for _, failure := range []string{"tail", "commit"} {
		t.Run(failure, func(t *testing.T) {
			s, cert := batchFixture(t)
			if err := s.st.Update(func(tx *sql.Tx) error {
				if failure == "tail" {
					_, err := tx.Exec(`CREATE TRIGGER fail_tail BEFORE UPDATE OF last_src_ip ON agents WHEN NEW.last_src_ip='fail' BEGIN SELECT RAISE(ABORT,'injected tail failure'); END`)
					return err
				}
				if _, err := tx.Exec(`CREATE TABLE deferred_batch_failure(id TEXT REFERENCES hosts(host_id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
					return err
				}
				_, err := tx.Exec(`CREATE TRIGGER fail_commit AFTER INSERT ON ingest_events BEGIN INSERT INTO deferred_batch_failure VALUES('missing'); END`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			jobs := []*batchJob{
				coalescedJob(t, s, cert, "before", 1),
				coalescedJob(t, s, cert, "bad", 2),
				coalescedJob(t, s, cert, "after", 3),
			}
			jobs[1].src = "fail"
			s.batchGate().commit(jobs)
			for i, j := range jobs {
				wantError := failure == "commit" || i == 1
				if wantError {
					if j.err == nil || len(j.res.Ack) != 0 {
						t.Fatalf("failed batch %d acknowledged: %+v %v", i, j.res, j.err)
					}
				} else if j.err != nil || len(j.res.Ack) != 1 {
					t.Fatalf("neighbour %d failed: %+v %v", i, j.res, j.err)
				}
			}
			want := 2
			if failure == "commit" {
				want = 0
			}
			if got := ingestCount(t, s); got != want {
				t.Fatalf("persisted events %d, want %d", got, want)
			}
			if err := s.st.Update(func(tx *sql.Tx) error {
				_, err := tx.Exec("DROP TRIGGER fail_" + failure)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// Retry the same event IDs: rolled-back data must be accepted,
			// committed neighbours must not be applied twice.
			for _, j := range jobs {
				j.err = nil
				j.done = make(chan struct{})
			}
			s.batchGate().commit(jobs)
			for _, j := range jobs {
				if j.err != nil || len(j.res.Ack) != 1 {
					t.Fatalf("retry failed: %+v %v", j.res, j.err)
				}
			}
			if got := ingestCount(t, s); got != 3 {
				t.Fatalf("retry event count %d", got)
			}
		})
	}
}

func coalesceEvent(id string, seq int64) protocol.Event {
	e := reviewQuestion(id, seq, 1)
	var p protocol.QuestionPayload
	_ = json.Unmarshal(e.Payload, &p)
	p.DedupKey = id
	e.Payload, _ = json.Marshal(p)
	return e
}
