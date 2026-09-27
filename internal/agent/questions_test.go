package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestQuestionQueueAtomicOfflineRestartAndAck(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{st: st}
	q := protocol.QuestionPayload{RemoteIP: "198.18.51.1", Protocol: "tcp", Direction: "out", RemotePort: 443}
	if err = a.Enqueue("question", 7, q); err != nil {
		t.Fatal(err)
	}
	var id string
	st.DB.QueryRow("SELECT question_id FROM local_questions").Scan(&id)
	st.Close()
	st, err = store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a.st = st
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "down", 503)
			return
		}
		var b protocol.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
		}
		if len(b.Events) != 1 || b.Events[0].EventID != id {
			t.Error("event changed on restart", b)
		}
		json.NewEncoder(w).Encode(protocol.Ack{Ack: []string{id}})
	}))
	defer srv.Close()
	a.client = srv.Client()
	a.cfg.Monitor = srv.URL
	if err = a.Flush(); err == nil {
		t.Fatal("HTTP failure hidden")
	}
	var n int
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 1 {
		t.Fatal("unacked question deleted")
	}
	fail = false
	st.DB.Exec("CREATE TRIGGER fail_remove BEFORE DELETE ON local_questions BEGIN SELECT RAISE(ABORT,'disk'); END")
	if err = a.Flush(); err == nil {
		t.Fatal("delete failure hidden")
	}
	st.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n)
	if n != 1 {
		t.Fatal("partial ACK deletion")
	}
	st.DB.Exec("DROP TRIGGER fail_remove")
	if err = a.Flush(); err != nil {
		t.Fatal(err)
	}
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 0 {
		t.Fatal("ACK not consumed")
	}
	st.DB.Exec("CREATE TRIGGER fail_insert BEFORE INSERT ON local_questions BEGIN SELECT RAISE(ABORT,'full'); END")
	if err = a.Enqueue("question", 7, q); err == nil {
		t.Fatal("queue failure hidden")
	}
	st.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n)
	if n != 0 {
		t.Fatal("half queued question")
	}
}
