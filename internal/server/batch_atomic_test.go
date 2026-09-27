package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func batchFixture(t *testing.T) (*Server, *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cert := &x509.Certificate{Raw: []byte("test-client-certificate")}
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id) VALUES('h')`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h',?,'trusted',1)`, tlsutil.Fingerprint(cert.Raw))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{st: st, cfg: Config{DataDir: dir}, startedMS: store.NowMS()}, cert
}

func scanEvent(id string, seq int64) protocol.Event {
	raw, _ := json.Marshal(protocol.ScanPayload{IP: "203.0.113.50", Ports: []int{22, 80, 443, 3306, 8080}})
	return protocol.Event{EventID: id, Seq: seq, Kind: "scan", ObservedAtMS: store.NowMS(), Payload: raw}
}

func sendBatch(t *testing.T, s *Server, cert *x509.Certificate, events ...protocol.Event) (int, protocol.Ack) {
	t.Helper()
	raw, err := json.Marshal(protocol.Batch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	var ack protocol.Ack
	if w.Code == 200 || w.Code == 409 {
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, ack
}

func TestBatchPartialAckAndReplayAfterReopen(t *testing.T) {
	s, cert := batchFixture(t)
	first := scanEvent("first", 1)
	bad := protocol.Event{EventID: "bad", Seq: 2, Kind: "missing", ObservedAtMS: 1, Payload: json.RawMessage(`{}`)}
	code, ack := sendBatch(t, s, cert, first, bad)
	if code != 409 || len(ack.Ack) != 1 || ack.Ack[0] != "first" {
		t.Fatalf("partial: %d %+v", code, ack)
	}
	var bans int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM blocks`).Scan(&bans); err != nil || bans != 1 {
		t.Fatalf("prefix effect missing: %d %v", bans, err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := tx.Exec(`UPDATE blocks SET state='removed'`); return err }); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(s.st.Path())
	if err := s.st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s.st = st
	code, ack = sendBatch(t, s, cert, first)
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("replay: %d %+v", code, ack)
	}
	// audit_log: строка автобана и строка тревоги. Повтор события новых не добавляет.
	for table, want := range map[string]int{"blocks": 1, "commands": 1, "audit_log": 2, "ingest_events": 1} {
		var n int
		if err := st.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("%s=%d want %d", table, n, want)
		}
	}
}

func TestBatchEffectFailureAndCommitFailureNeverAck(t *testing.T) {
	for _, failure := range []string{"command", "commit"} {
		t.Run(failure, func(t *testing.T) {
			s, cert := batchFixture(t)
			if err := s.st.Update(func(tx *sql.Tx) error {
				if failure == "command" {
					_, err := tx.Exec(`CREATE TRIGGER fail_command BEFORE INSERT ON commands BEGIN SELECT RAISE(ABORT,'injected command failure'); END`)
					return err
				}
				if _, err := tx.Exec(`CREATE TABLE deferred_failure(id TEXT REFERENCES hosts(host_id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
					return err
				}
				_, err := tx.Exec(`CREATE TRIGGER fail_commit AFTER INSERT ON ingest_events BEGIN INSERT INTO deferred_failure VALUES('missing'); END`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			first := scanEvent("scan", 1)
			if code, ack := sendBatch(t, s, cert, first); code != 500 || len(ack.Ack) != 0 {
				t.Fatalf("failed write acked: %d %+v", code, ack)
			}
			for _, table := range []string{"ingest_events", "blocks", "commands", "audit_log"} {
				var n int
				if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Fatalf("%s survived failed commit: %d", table, n)
				}
			}
			if err := s.st.Update(func(tx *sql.Tx) error { _, err := tx.Exec("DROP TRIGGER fail_" + failure); return err }); err != nil {
				t.Fatal(err)
			}
			if code, ack := sendBatch(t, s, cert, first); code != 200 || len(ack.Ack) != 1 {
				t.Fatalf("retry: %d %+v", code, ack)
			}
		})
	}
}

func TestPendingCannotAutoban(t *testing.T) {
	s, cert := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := tx.Exec(`UPDATE agents SET trust_state='pending'`); return err }); err != nil {
		t.Fatal(err)
	}
	if code, ack := sendBatch(t, s, cert, scanEvent("pending", 1)); code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("pending telemetry: %d %+v", code, ack)
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM blocks`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("pending agent triggered autoban")
	}
}
