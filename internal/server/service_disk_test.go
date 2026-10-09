package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestServiceDiskKeepsQuestionAndDropsFlow(t *testing.T) {
	s, cert := batchFixture(t)

	s.session = "sess-1"
	flow := flowEvent("f1", 1, openFlow("uid-1"))
	code, ack := sendBatch(t, s, cert, flow)
	if code != 200 || len(ack.Ack) != 1 || ack.Ack[0] != "f1" || ack.Session != "sess-1" {
		t.Fatalf("flow ack %d %+v", code, ack)
	}
	if n := countTable(t, s, "open_flows"); n != 0 {
		t.Fatalf("open_flows %d", n)
	}
	if n := countTable(t, s, "ingest_events"); n != 0 {
		t.Fatalf("ingest %d", n)
	}
	if n := countTable(t, s, "flows"); n != 0 {
		t.Fatalf("flows %d", n)
	}
	raw, _ := json.Marshal(protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, ProcComm: "curl", DedupKey: "q"})
	q := protocol.Event{EventID: "q1", Seq: 2, Kind: "question", ObservedAtMS: store.NowMS(), Payload: raw}
	code, ack = sendBatch(t, s, cert, q)
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("question %d %+v", code, ack)
	}
	q.EventID = "q2"
	q.Seq = 3
	code, ack = sendBatch(t, s, cert, q)
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("repeat %d %+v", code, ack)
	}
	var n, repeats int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(repeats),0) FROM learn_questions`).Scan(&n, &repeats); err != nil {
		t.Fatal(err)
	}
	if n != 1 || repeats != 1 {
		t.Fatalf("questions %d repeats %d", n, repeats)
	}
	body, _ := json.Marshal(protocol.Batch{Session: "old", Events: []protocol.Event{flow}})
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	if w.Code != 409 {
		t.Fatalf("old session %d %s", w.Code, w.Body.String())
	}
	if got := s.visibleReports(); len(got) != 4 {
		t.Fatalf("reports %d", len(got))
	}
}
