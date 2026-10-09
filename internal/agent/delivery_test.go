package agent

import (
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
	a := &Agent{st: st, client: srv.Client(), cfg: Config{Monitor: srv.URL}, session: "test-session"}
	for _, ev := range []struct {
		kind string
		pri  int
		p    any
	}{
		{"sample", 0, map[string]string{"x": "old"}},
		{"question", 7, protocol.QuestionPayload{RemoteIP: "1.1.1.1"}},
		{"health", 10, protocol.HealthPayload{Kind: "alive"}},
	} {
		if err := a.Enqueue(ev.kind, ev.pri, ev.p); err != nil {
			t.Fatal(err)
		}
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

func seqsOf(events []protocol.Event) []int64 {
	out := make([]int64, len(events))
	for i, event := range events {
		out[i] = event.Seq
	}
	return out
}

func hasSeq(seqs []int64, want int64) bool {
	for _, seq := range seqs {
		if seq == want {
			return true
		}
	}
	return false
}
