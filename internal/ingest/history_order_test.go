package ingest_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestHistoryCannotReopenOrRollBackFlow(t *testing.T) {
	st, e := store.OpenMonitor(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = st.Update(func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h','test',1,1)"); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	ag := ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}
	end := int64(62000)
	count := int64(300)
	port := 443
	f := protocol.FlowPayload{FlowUID: "uid", BootID: "boot", IPVersion: 4, Protocol: "tcp", Direction: "in", OrigSrcIP: "203.0.113.1", OrigDstIP: "10.0.0.2", LocalIP: "10.0.0.2", RemoteIP: "203.0.113.1", LocalPort: &port, OrigBytes: &count, FirstSeenMS: 59000, LastSeenMS: 62000, EndedAtMS: &end, State: "TIME_WAIT", CloseReason: "fin", ReplySeen: 1, ProcComm: "httpd"}
	apply := func(seq int64, kind string, p any) {
		t.Helper()
		raw, _ := json.Marshal(p)
		e := st.Update(func(tx *sql.Tx) error {
			r := ingest.ApplyBatch(tx, ag, []protocol.Event{{EventID: fmt.Sprint(seq), Seq: seq, Kind: kind, ObservedAtMS: 62000, Payload: raw}}, 63000)
			if r.Fatal != nil {
				return r.Fatal
			}
			if r.Err != "" {
				return fmt.Errorf("%s", r.Err)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	apply(3, "flow", f)
	f.EndedAtMS = nil
	f.State = "SYN_RECV"
	f.ReplySeen = 0
	f.LastSeenMS = 60000
	oldCount := int64(100)
	f.OrigBytes = &oldCount
	apply(1, "flow", f)
	sample := protocol.SamplePayload{FlowUID: "uid", Flow: &f, T0MS: 59000, T1MS: 61000, OrigBytesDelta: 101, ReplyBytesDelta: 51, Direction: "in", RemoteScope: "internet", Quality: "ok"}
	apply(2, "sample", sample)
	var ended, bytes, seq int64
	var state string
	if e = st.DB.QueryRow("SELECT ended_at_ms,orig_bytes,state_seq,state FROM flows").Scan(&ended, &bytes, &seq, &state); e != nil {
		t.Fatal(e)
	}
	if ended != 62000 || bytes != 300 || seq != 3 || state != "TIME_WAIT" {
		t.Fatalf("%d %d %d %s", ended, bytes, seq, state)
	}
	var in, out, flows, last int64
	st.DB.QueryRow("SELECT SUM(bytes_in),SUM(bytes_out) FROM traffic_1m").Scan(&in, &out)
	if in != 101 || out != 51 {
		t.Fatal("minute sum or incoming direction", in, out)
	}
	st.DB.QueryRow("SELECT flows FROM remote_seen").Scan(&flows)
	if flows != 1 {
		t.Fatal("updates counted as new contacts", flows)
	}
	st.DB.QueryRow("SELECT last_seen_ms FROM hosts").Scan(&last)
	if last != 1 {
		t.Fatal("history faked liveness")
	}
	apply(4, "health", protocol.HealthPayload{Kind: "alive"})
	st.DB.QueryRow("SELECT last_seen_ms FROM hosts").Scan(&last)
	if last != 63000 {
		t.Fatal("fresh heartbeat missing")
	}
}

func TestHeartbeatLaneSurvivesClockJump(t *testing.T) {
	st, e := store.OpenMonitor(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = st.Update(func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO hosts(host_id,last_seen_ms) VALUES('h',1)"); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.HealthPayload{Kind: "alive", BootID: "boot"})
	ag := ingest.Agent{ID: "a", HostID: "h", Trust: "trusted", DeliveryLane: "heartbeat"}
	ev := protocol.Event{EventID: "alive1", Seq: 1, Kind: "health", ObservedAtMS: 1000, Payload: raw}
	if e = st.Update(func(tx *sql.Tx) error {
		r := ingest.ApplyBatch(tx, ag, []protocol.Event{ev}, 1_000_000)
		if r.Fatal != nil {
			return r.Fatal
		}
		if r.Err != "" {
			return fmt.Errorf("%s", r.Err)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var last int64
	st.DB.QueryRow("SELECT last_seen_ms FROM hosts").Scan(&last)
	if last != 1_000_000 {
		t.Fatal(last)
	}
	ag.DeliveryLane = "history"
	ev.EventID = "alive2"
	ev.Seq = 2
	ev.ObservedAtMS = 1_000_001
	if e = st.Update(func(tx *sql.Tx) error {
		r := ingest.ApplyBatch(tx, ag, []protocol.Event{ev}, 1_000_002)
		return r.Fatal
	}); e != nil {
		t.Fatal(e)
	}
	st.DB.QueryRow("SELECT last_seen_ms FROM hosts").Scan(&last)
	if last != 1_000_000 {
		t.Fatal("history changed liveness", last)
	}
}
