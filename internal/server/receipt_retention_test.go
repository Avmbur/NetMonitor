package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func receiptSample(t *testing.T, s *Server, ms int64) protocol.Event {
	t.Helper()
	_, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ended_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
 VALUES('retry-flow','h','a','b',?,?,?,4,'tcp','10.0.0.1',zeroblob(16),'203.0.113.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'203.0.113.1',zeroblob(16),'internet','host',?)`, ms, ms, ms, ms)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(protocol.SamplePayload{FlowUID: "retry-flow", T0MS: ms, T1MS: ms + 1000, OrigBytesDelta: 100, OrigPacketsDelta: 1, Direction: "out", RemoteScope: "internet", Quality: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Event{EventID: "retry-event", Seq: 1, Kind: "sample", ObservedAtMS: ms + 1000, Payload: raw}
}

func receiveAt(t *testing.T, s *Server, ev protocol.Event, now int64) ingest.Result {
	t.Helper()
	var result ingest.Result
	err := s.st.Update(func(tx *sql.Tx) error {
		result = ingest.ApplyBatch(tx, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, []protocol.Event{ev}, now)
		return result.Fatal
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPendingReplaySurvivesRetentionAndConfirmation(t *testing.T) {
	for _, days := range []int{15, 120} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			s, cert := batchFixture(t)
			now := time.Now().UTC().Truncate(time.Minute).UnixMilli()
			old := now - int64(days)*86400000
			ev := receiptSample(t, s, old)
			first := receiveAt(t, s, ev, old)
			if first.Err != "" || len(first.Ack) != 1 {
				t.Fatalf("first: %+v", first)
			}
			if err := s.retainNow(now); err != nil {
				t.Fatal(err)
			}
			repeat := receiveAt(t, s, ev, now)
			if repeat.Err != "" || len(repeat.Ack) != 1 {
				t.Fatalf("lost ACK retry: %+v", repeat)
			}
			changed := ev
			changed.Payload = append(append([]byte(nil), ev.Payload...), byte(' '))
			if bad := receiveAt(t, s, changed, now); bad.Err == "" || len(bad.Ack) != 0 {
				t.Fatalf("changed pending payload accepted: %+v", bad)
			}
			var before int
			if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM flow_samples").Scan(&before); err != nil {
				t.Fatal(err)
			}
			floor := int64(2)
			if code, ack := sendPendingBatch(t, s, cert, floor); code != 200 || len(ack.Ack) != 0 {
				t.Fatalf("confirm: %d %+v", code, ack)
			}
			var receipts int
			if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM ingest_events").Scan(&receipts); err != nil || receipts != 0 {
				t.Fatalf("confirmed receipts retained: %d %v", receipts, err)
			}
			// A request prepared before confirmation may arrive after it.
			if code, ack := sendPendingBatch(t, s, cert, 1, ev); code != 200 || len(ack.Ack) != 1 {
				t.Fatalf("late request: %d %+v", code, ack)
			}
			var after int
			if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM flow_samples").Scan(&after); err != nil || after != before {
				t.Fatalf("replay applied again: %d -> %d: %v", before, after, err)
			}
			if _, err := os.Stat(filepath.Join(s.dataDir(), "archives")); !os.IsNotExist(err) {
				t.Fatalf("unexpected archive directory: %v", err)
			}
		})
	}
}

func sendPendingBatch(t *testing.T, s *Server, cert *x509.Certificate, floor int64, events ...protocol.Event) (int, protocol.Ack) {
	t.Helper()
	raw, err := json.Marshal(protocol.Batch{PendingFrom: &floor, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(raw))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, req)
	var ack protocol.Ack
	if w.Code == 200 || w.Code == 409 {
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, ack
}

func TestInvalidConfirmationDoesNotErasePendingReceipts(t *testing.T) {
	s, cert := batchFixture(t)
	ev := receiptSample(t, s, time.Now().UTC().Truncate(time.Minute).UnixMilli())
	if first := receiveAt(t, s, ev, store.NowMS()); first.Err != "" {
		t.Fatal(first)
	}
	if code, _ := sendPendingBatch(t, s, cert, 2, ev); code != 400 {
		t.Fatalf("invalid floor accepted: %d", code)
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM ingest_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("receipt erased: %d %v", n, err)
	}
}

func TestBoundedDatabaseAcrossRepeatedBatches(t *testing.T) {
	s, _ := batchFixture(t)
	const limit = 1 << 20
	if err := s.st.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "db_max_bytes", fmt.Sprint(limit)) }); err != nil {
		t.Fatal(err)
	}
	now := store.NowMS()
	for round := 0; round < 20; round++ {
		first := int64(round*200 + 1)
		events := make([]protocol.Event, 200)
		for i := range events {
			seq := first + int64(i)
			events[i] = protocol.Event{EventID: fmt.Sprintf("bounded-%d", seq), Seq: seq, Kind: "health", ObservedAtMS: now, Payload: json.RawMessage(`{"kind":"alive"}`)}
		}
		if err := s.st.Update(func(tx *sql.Tx) error {
			if err := ingest.ConfirmQueue(tx, "a", first); err != nil {
				return err
			}
			result := ingest.ApplyBatch(tx, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, events, now)
			if result.Fatal != nil {
				return result.Fatal
			}
			if result.Err != "" || len(result.Ack) != len(events) {
				return fmt.Errorf("batch: %+v", result)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.st.Update(func(tx *sql.Tx) error { return ingest.ConfirmQueue(tx, "a", first+200) }); err != nil {
			t.Fatal(err)
		}
		if err := s.enforceDbCap(); err != nil {
			t.Fatal(err)
		}
		if size := s.dbFileBytes(); size > limit {
			t.Fatalf("round %d: %d > %d", round, size, limit)
		}
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM ingest_events").Scan(&n); err != nil || n != 0 {
		t.Fatalf("receipts=%d %v", n, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.takeSnapshot(); err != nil {
			t.Fatal(err)
		}
	}
	var databases []string
	if err := filepath.WalkDir(s.dataDir(), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".sqlite" {
			databases = append(databases, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(databases) != 2 {
		t.Fatalf("want working database and one snapshot: %v", databases)
	}
	t.Logf("4000 events; main+WAL=%d, limit=%d; SQLite files=%d", s.dbFileBytes(), limit, len(databases))
}

func TestConfirmationSurvivesSnapshotRestore(t *testing.T) {
	s, cert := batchFixture(t)
	ev := receiptSample(t, s, time.Now().UTC().Truncate(time.Minute).UnixMilli())
	if result := receiveAt(t, s, ev, store.NowMS()); result.Err != "" {
		t.Fatal(result)
	}
	if code, _ := sendPendingBatch(t, s, cert, 2); code != 200 {
		t.Fatal(code)
	}
	dir := t.TempDir()
	if err := s.st.BackupTo(filepath.Join(dir, "netmon.sqlite")); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	restored := &Server{st: st, cfg: Config{DataDir: dir}}
	if code, ack := sendPendingBatch(t, restored, cert, 1, ev); code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("restored replay: %d %+v", code, ack)
	}
	var n int
	if err := st.DB.QueryRow("SELECT COUNT(*) FROM flow_samples").Scan(&n); err != nil || n != 1 {
		t.Fatalf("restored stats: %d %v", n, err)
	}
}

func TestCapShrinksOversizedHistoryWithoutExtraDatabase(t *testing.T) {
	s, _ := batchFixture(t)
	// Seed an oversized old database before applying the new allocation guard.
	if _, err := s.st.DB.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<300)
 INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) SELECT 'old-'||x,x,'adm','old',hex(randomblob(4096)) FROM n`); err != nil {
		t.Fatal(err)
	}
	if before := s.dbFileBytes(); before <= 1<<20 {
		t.Fatalf("fixture not oversized: %d", before)
	}
	const limit = 1 << 20
	if err := s.st.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "db_max_bytes", fmt.Sprint(limit)) }); err != nil {
		t.Fatal(err)
	}

	if err := s.enforceDbCap(); err != nil {
		t.Fatal(err)
	}
	if after := s.dbFileBytes(); after > limit {
		t.Fatalf("history not compacted: %d", after)
	}
	var agents int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM agents").Scan(&agents); err != nil || agents != 1 {
		t.Fatalf("agent lost: %d %v", agents, err)
	}
	if _, err := os.Stat(filepath.Join(s.dataDir(), "archives")); !os.IsNotExist(err) {
		t.Fatalf("extra database directory: %v", err)
	}
	if err := store.Integrity(s.st.Path()); err != nil {
		t.Fatal(err)
	}
	t.Logf("oversized history reduced to main+WAL=%d, limit=%d", s.dbFileBytes(), limit)
}

func TestFullDatabaseDoesNotAckAndRecovers(t *testing.T) {
	s, cert := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "db_max_bytes", fmt.Sprint(1<<20)); err != nil {
			return err
		}
		_, err := tx.Exec("CREATE TABLE filler(payload TEXT)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	full := false
	for i := 0; i < 100; i++ {
		err := s.st.Update(func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO filler VALUES(?)", strings.Repeat("x", 32768))
			return err
		})
		if err != nil {
			if !strings.Contains(err.Error(), "full") {
				t.Fatal(err)
			}
			full = true
			break
		}
	}
	if !full {
		t.Fatal("allocation guard did not stop growth")
	}
	raw, err := json.Marshal(protocol.HealthPayload{Kind: "test-full", Note: strings.Repeat("z", 400000)})
	if err != nil {
		t.Fatal(err)
	}
	ev := protocol.Event{EventID: "full-event", Seq: 1, Kind: "health", ObservedAtMS: store.NowMS(), Payload: raw}
	code, ack := sendPendingBatch(t, s, cert, 1, ev)
	if code == 200 || len(ack.Ack) != 0 {
		t.Fatalf("full database acknowledged data: %d %+v", code, ack)
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM ingest_events").Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial receipt survived: %d %v", n, err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := tx.Exec("DELETE FROM filler"); return err }); err != nil {
		t.Fatal(err)
	}
	code, ack = sendPendingBatch(t, s, cert, 1, ev)
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("retry after freeing space: %d %+v", code, ack)
	}
	if size := s.dbFileBytes(); size > 1<<20 {
		t.Fatalf("limit exceeded: %d", size)
	}
}

func TestIncomingHistoryRotatesWithoutRejectedBatches(t *testing.T) {
	s, cert := batchFixture(t)
	const limit = 1 << 20
	if err := s.st.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "db_max_bytes", fmt.Sprint(limit)) }); err != nil {
		t.Fatal(err)
	}
	now := store.NowMS()
	payload, err := json.Marshal(protocol.HealthPayload{Kind: "rotation-test", Note: strings.Repeat("x", 16384)})
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 200; i++ {
		ev := protocol.Event{EventID: fmt.Sprintf("rotate-%d", i), Seq: i, Kind: "health", ObservedAtMS: now + i, Payload: payload}
		code, ack := sendPendingBatch(t, s, cert, i, ev)
		if code != 200 || len(ack.Ack) != 1 {
			t.Fatalf("write %d: %d %+v", i, code, ack)
		}
		var n int
		if err := s.st.DB.QueryRow("SELECT count(*) FROM collector_health WHERE event_id=?", ev.EventID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("new event missing: %d %v", n, err)
		}
		if size := s.dbFileBytes(); size > limit {
			t.Fatalf("write %d exceeded limit: %d", i, size)
		}
	}
	var n int
	var oldest, newest int64
	if err := s.st.DB.QueryRow("SELECT count(*),min(observed_at_ms),max(observed_at_ms) FROM collector_health WHERE kind='rotation-test'").Scan(&n, &oldest, &newest); err != nil {
		t.Fatal(err)
	}
	if n >= 200 || oldest != now+201-int64(n) || newest != now+200 {
		t.Fatalf("not oldest first: count=%d range=%d..%d", n, oldest-now, newest-now)
	}
	if err := store.Integrity(s.st.Path()); err != nil {
		t.Fatal(err)
	}
	t.Logf("200/200 ACK; retained last %d events; main+WAL=%d <= %d", n, s.dbFileBytes(), limit)
}
