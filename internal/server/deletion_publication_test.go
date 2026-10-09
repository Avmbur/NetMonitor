package server

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

// Pause after TLS authentication so its own write does not enter the batch barrier.
type deletionBatchBody struct {
	ready, proceed chan struct{}
	sent           bool
	data           []byte
}

func (b *deletionBatchBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		close(b.ready)
		<-b.proceed
	}
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func TestAgentDeletionWaitsForBatchPublication(t *testing.T) {
	for _, mode := range []string{"delete", "uninstall", "failed_delete"} {
		t.Run(mode, func(t *testing.T) {
			s, cert := batchFixture(t)
			var command string
			if mode == "uninstall" {
				s.hostSeen = map[string]int64{"h": store.NowMS()}
				if _, err := s.st.DB.Exec("UPDATE hosts SET last_seen_ms=?", store.NowMS()); err != nil {
					t.Fatal(err)
				}
				if err := s.changeAgent("a", "remove", "", ""); err != nil {
					t.Fatal(err)
				}
				if err := s.st.DB.QueryRow("SELECT command_id FROM commands WHERE agent_id='a'").Scan(&command); err != nil {
					t.Fatal(err)
				}
				if _, err := s.st.DB.Exec("UPDATE commands SET delivered_at_ms=1,result='removing' WHERE command_id=?", command); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "failed_delete" {
				if _, err := s.st.DB.Exec("CREATE TRIGGER reject_delete BEFORE DELETE ON agents BEGIN SELECT RAISE(ABORT,'review deletion failure'); END"); err != nil {
					t.Fatal(err)
				}
			}
			p := openFlow("delete-publication")
			end := p.LastSeenMS
			payload, err := json.Marshal(protocol.SamplePayload{
				FlowUID: p.FlowUID, Flow: &p, T0MS: end - 1000, T1MS: end, OrigBytesDelta: 1234567,
				Direction: "out", RemoteScope: "internet", Quality: "ok",
			})
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(protocol.Batch{Session: s.session, Instance: "test-process", Events: []protocol.Event{{
				EventID: "delete-publication-sample", Seq: 1, Kind: "sample", ObservedAtMS: end, Payload: payload,
			}}})
			if err != nil {
				t.Fatal(err)
			}
			reader := &deletionBatchBody{ready: make(chan struct{}), proceed: make(chan struct{}), data: body}
			req := httptest.NewRequest("POST", "/v1/batch", reader)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			rec := httptest.NewRecorder()
			requestDone := make(chan struct{})
			go func() { s.handleBatch(rec, req); close(requestDone) }()
			select {
			case <-reader.ready:
			case <-time.After(3 * time.Second):
				t.Fatal("authentication did not finish")
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			released := false
			writerDone := make(chan error, 1)
			go func() { writerDone <- s.st.Update(func(tx *sql.Tx) error { close(entered); <-release; return nil }) }()
			<-entered
			defer func() {
				if !released {
					close(release)
				}
			}()
			// Observe only queue length: no mutation of store internals or production hooks.
			queued := func() int { return reflect.ValueOf(s.st).Elem().FieldByName("o").Elem().FieldByName("jobs").Len() }
			close(reader.proceed)
			deadline := time.Now().Add(3 * time.Second)
			for queued() < 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if queued() < 1 {
				t.Fatal("batch did not reach writer")
			}
			deleteDone := make(chan error, 1)
			deletionStarted := make(chan struct{})
			go func() {
				close(deletionStarted)
				if mode == "uninstall" {
					deleteDone <- s.recordUninstall(tlsutil.Fingerprint(cert.Raw), protocol.UninstallResult{CommandID: command, Phase: "complete"})
				} else {
					deleteDone <- s.changeAgent("a", "delete", "", "test")
				}
			}()
			<-deletionStarted
			// The old implementation queues deletion behind the batch while holding flushMu.
			// The fix waits for publication before entering the writer at all.
			deadline = time.Now().Add(100 * time.Millisecond)
			for queued() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			close(release)
			released = true
			if err := <-writerDone; err != nil {
				t.Fatal(err)
			}
			var deleteErr error
			select {
			case deleteErr = <-deleteDone:
			case <-time.After(3 * time.Second):
				t.Fatal("deletion blocked")
			}
			select {
			case <-requestDone:
			case <-time.After(3 * time.Second):
				t.Fatal("publication blocked")
			}
			if mode == "failed_delete" {
				if deleteErr == nil {
					t.Fatal("delete should fail")
				}
			} else if deleteErr != nil {
				t.Fatal(deleteErr)
			}
			if rec.Code != 200 {
				t.Fatalf("batch status %d: %s", rec.Code, rec.Body.String())
			}
			n, _, _, err := s.liveActivity("", false, true)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "failed_delete" {
				want = 1
			}
			if n != want {
				t.Fatalf("live after %s: %d, want %d", mode, n, want)
			}
			if mode != "failed_delete" && len(s.live.open) != 0 {
				t.Fatal("deleted agent retained live state")
			}

		})
	}
}
