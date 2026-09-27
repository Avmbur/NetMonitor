package agent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"sync"
	"testing"
	"time"
)

func TestHistoryRequestCannotDelayUrgentAndHeartbeat(t *testing.T) {
	st, e := store.OpenAgent(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	blocked := make(chan bool, 1)
	release := make(chan bool)
	var once sync.Once
	defer once.Do(func() { close(release) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b protocol.Batch
		if e := json.NewDecoder(r.Body).Decode(&b); e != nil {
			t.Error(e)
			return
		}
		if b.Events[0].Kind == "sample" {
			blocked <- true
			<-release
		}
		ack := protocol.Ack{}
		for _, e := range b.Events {
			ack.Ack = append(ack.Ack, e.EventID)
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer srv.Close()
	a := &Agent{st: st, client: srv.Client(), cfg: Config{Monitor: srv.URL}}
	if e = st.Update(func(tx *sql.Tx) error {
		if e := enqueueTx(tx, "sample", 0, map[string]string{"x": "old"}); e != nil {
			return e
		}
		if e := enqueueTx(tx, "question", 7, protocol.QuestionPayload{RemoteIP: "1.1.1.1"}); e != nil {
			return e
		}
		return enqueueTx(tx, "health", 10, protocol.HealthPayload{Kind: "alive"})
	}); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- a.flushLane("history") }()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("history not started")
	}
	start := time.Now()
	for _, lane := range []string{"urgent", "heartbeat"} {
		if e = a.flushLane(lane); e != nil {
			t.Fatal(e)
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("urgent delivery delayed")
	}
	var n int
	st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE lane<>'history'").Scan(&n)
	if n != 0 {
		t.Fatal(fmt.Sprint(n, " urgent events left"))
	}
	once.Do(func() { close(release) })
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestQueueConfirmationWaitsForLostAckAndAllLanes(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var batches []protocol.Batch
	var mu sync.Mutex
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b protocol.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		batches = append(batches, b)
		failed := fail
		mu.Unlock()
		if failed {
			w.WriteHeader(500)
			return
		}
		ack := protocol.Ack{}
		for _, event := range b.Events {
			ack.Ack = append(ack.Ack, event.EventID)
		}
		json.NewEncoder(w).Encode(ack)
	}))
	defer srv.Close()
	a := &Agent{st: st, client: srv.Client(), cfg: Config{Monitor: srv.URL}}
	if err := a.Enqueue("sample", 0, map[string]string{"old": "history"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "alive"}); err != nil {
		t.Fatal(err)
	}
	if err := a.flushLane("heartbeat"); err == nil {
		t.Fatal("expected lost ACK")
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if err := a.flushLane("heartbeat"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	firstBatches := append([]protocol.Batch(nil), batches...)
	mu.Unlock()
	if len(firstBatches) != 2 {
		t.Fatal(len(firstBatches))
	}
	for _, b := range firstBatches {
		if b.PendingFrom == nil || *b.PendingFrom != 1 {
			t.Fatalf("history was skipped: %+v", b)
		}
		if len(b.Events) != 1 || b.Events[0].Seq != 2 {
			t.Fatalf("unexpected heartbeat: %+v", b)
		}
	}
	if err := a.flushLane("history"); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "alive"}); err != nil {
		t.Fatal(err)
	}
	if err := a.flushLane("heartbeat"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	last := batches[len(batches)-1]
	mu.Unlock()
	if last.PendingFrom == nil || *last.PendingFrom != 3 {
		t.Fatalf("completed queue not confirmed: %+v", last)
	}
}
