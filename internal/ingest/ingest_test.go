package ingest_test

import (
	"database/sql"
	"encoding/json"
	"testing"

	"netmonitor/internal/idgen"
	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestDuplicateAndConflict(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	host := idgen.NewV7()
	agID := idgen.NewV7()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,1,1)`, host, "t"); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, first_seen_ms) VALUES(?,?,?,?,1)`,
			agID, host, "fp", "pending")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ag := ingest.Agent{ID: agID, HostID: host, Trust: "pending"}
	port := 443
	flow := protocol.FlowPayload{
		FlowUID: "f1", BootID: "b", IPVersion: 4, Protocol: "tcp",
		OrigSrcIP: "10.0.0.2", OrigDstIP: "8.8.8.8", Direction: "out",
		LocalIP: "10.0.0.2", RemoteIP: "8.8.8.8", FirstSeenMS: 10, LastSeenMS: 11,
		OrigDstPort: &port, RemotePort: &port,
	}
	raw, _ := json.Marshal(flow)
	ev := protocol.Event{EventID: "e1", Seq: 1, Kind: "flow", ObservedAtMS: 10, Payload: raw}
	if err := st.Update(func(tx *sql.Tx) error {
		r := ingest.ApplyBatch(tx, ag, []protocol.Event{ev}, 20)
		if r.Err != "" || len(r.Ack) != 1 {
			t.Fatalf("first %+v", r)
		}
		r = ingest.ApplyBatch(tx, ag, []protocol.Event{ev}, 21)
		if r.Err != "" || len(r.Ack) != 1 {
			t.Fatalf("repeat %+v", r)
		}
		ev2 := ev
		flow.ReplySeen = 1
		raw2, _ := json.Marshal(flow)
		ev2.Payload = raw2
		r = ingest.ApplyBatch(tx, ag, []protocol.Event{ev2}, 22)
		if r.Err == "" {
			t.Fatal("ждали конфликт тела")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("flows=%d", n)
	}
}

func TestQuestionUpsert(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	host := idgen.NewV7()
	agID := idgen.NewV7()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,1,1)`, host, "t"); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, first_seen_ms) VALUES(?,?,?,?,1)`,
			agID, host, "fp", "trusted")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ag := ingest.Agent{ID: agID, HostID: host, Trust: "trusted"}
	raw, _ := json.Marshal(protocol.QuestionPayload{
		Direction: "out", Protocol: "tcp", RemoteIP: "1.1.1.1", RemotePort: 443, DedupKey: "out|tcp|1.1.1.1|443",
	})
	ev := protocol.Event{EventID: "q1", Seq: 10, Kind: "question", ObservedAtMS: 10, Payload: raw}
	if err := st.Update(func(tx *sql.Tx) error {
		r := ingest.ApplyBatch(tx, ag, []protocol.Event{ev}, 20)
		if r.Err != "" || len(r.Ack) != 1 {
			t.Fatalf("first %+v", r)
		}
		ev2 := ev
		ev2.EventID = "q2"
		ev2.Seq = 11
		r = ingest.ApplyBatch(tx, ag, []protocol.Event{ev2}, 21)
		if r.Err != "" || len(r.Ack) != 1 {
			t.Fatalf("repeat %+v", r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var n, repeats int
	if err := st.DB.QueryRow(`SELECT COUNT(*), MAX(repeats) FROM learn_questions WHERE status='open'`).Scan(&n, &repeats); err != nil {
		t.Fatal(err)
	}
	if n != 1 || repeats != 2 {
		t.Fatalf("questions=%d repeats=%d", n, repeats)
	}
}

func TestSkipSamplesAtDiskLimit(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h','t',1,1)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)`); err != nil {
			return err
		}
		return store.PutSetting(tx, "disk_skip_samples", "1")
	}); err != nil {
		t.Fatal(err)
	}
	ag := ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}
	flow := protocol.FlowPayload{
		FlowUID: "f1", BootID: "b", IPVersion: 4, Protocol: "tcp",
		OrigSrcIP: "10.0.0.2", OrigDstIP: "8.8.8.8", Direction: "out",
		LocalIP: "10.0.0.2", RemoteIP: "8.8.8.8", FirstSeenMS: 10, LastSeenMS: 11,
	}
	fraw, _ := json.Marshal(flow)
	sraw, _ := json.Marshal(protocol.SamplePayload{
		FlowUID: "f1", T0MS: 10, T1MS: 70, OrigBytesDelta: 100, Quality: "ok", Direction: "out", RemoteScope: "internet",
	})
	if err := st.Update(func(tx *sql.Tx) error {
		r := ingest.ApplyBatch(tx, ag, []protocol.Event{
			{EventID: "f", Seq: 1, Kind: "flow", ObservedAtMS: 10, Payload: fraw},
			{EventID: "s", Seq: 2, Kind: "sample", ObservedAtMS: 70, Payload: sraw},
		}, 80)
		if r.Err != "" || len(r.Ack) != 2 {
			t.Fatalf("%+v", r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var samples, flows int
	st.DB.QueryRow(`SELECT COUNT(*) FROM flow_samples`).Scan(&samples)
	st.DB.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&flows)
	if samples != 0 || flows != 1 {
		t.Fatalf("samples=%d flows=%d", samples, flows)
	}
}
