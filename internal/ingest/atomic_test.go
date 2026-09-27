package ingest_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func event(id string, seq int64, kind string, payload any) protocol.Event {
	raw, _ := json.Marshal(payload)
	return protocol.Event{EventID: id, Seq: seq, Kind: kind, ObservedAtMS: 100000, Payload: raw}
}

func ingestFixture(t *testing.T) (*store.Store, ingest.Agent) {
	t.Helper()
	s, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Update(func(tx *sql.Tx) error {
		for _, id := range []string{"a", "b"} {
			if _, err := tx.Exec(`INSERT INTO hosts(host_id) VALUES(?)`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES(?,?,?,'trusted',1)`, id, id, id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s, ingest.Agent{ID: "a", HostID: "a", Trust: "trusted"}
}

func testFlow(uid string) protocol.FlowPayload {
	return protocol.FlowPayload{FlowUID: uid, BootID: "boot", IPVersion: 4, Protocol: "tcp", OrigSrcIP: "10.0.0.1", OrigDstIP: "1.1.1.1", LocalIP: "10.0.0.1", RemoteIP: "1.1.1.1", Direction: "out", FirstSeenMS: 1, LastSeenMS: 100000}
}

func apply(t *testing.T, s *store.Store, ag ingest.Agent, evs ...protocol.Event) ingest.Result {
	t.Helper()
	var result ingest.Result
	if err := s.Update(func(tx *sql.Tx) error { result = ingest.ApplyBatch(tx, ag, evs, 120000); return result.Fatal }); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPartialAckRollsBackAllFailedEventWrites(t *testing.T) {
	s, ag := ingestFixture(t)
	if err := s.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER fail_sample BEFORE INSERT ON flow_samples WHEN NEW.t0_ms>=60000 BEGIN SELECT RAISE(ABORT,'injected sample failure'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	flow := testFlow("rollback-flow")
	sample := event("sample", 2, "sample", protocol.SamplePayload{Flow: &flow, FlowUID: flow.FlowUID, T0MS: 1, T1MS: 90000, OrigBytesDelta: 1000, Quality: "ok"})
	first := event("first", 1, "health", protocol.HealthPayload{Kind: "alive"})
	last := event("last", 3, "health", protocol.HealthPayload{Kind: "alive"})
	r := apply(t, s, ag, first, sample, last)
	if r.Err == "" || len(r.Ack) != 1 || r.Ack[0] != "first" {
		t.Fatalf("partial ack: %+v", r)
	}
	for table, want := range map[string]int{"ingest_events": 1, "collector_health": 1, "flows": 0, "remote_seen": 0, "flow_samples": 0, "traffic_1m": 0} {
		var n int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("%s=%d want %d", table, n, want)
		}
	}
	if err := s.Update(func(tx *sql.Tx) error { _, err := tx.Exec(`DROP TRIGGER fail_sample`); return err }); err != nil {
		t.Fatal(err)
	}
	r = apply(t, s, ag, first, sample, last)
	if r.Err != "" || len(r.Ack) != 3 {
		t.Fatalf("retry: %+v", r)
	}
	r = apply(t, s, ag, first, sample, last)
	if r.Err != "" || len(r.Ack) != 3 {
		t.Fatalf("duplicate: %+v", r)
	}
	var total int64
	if err := s.DB.QueryRow(`SELECT SUM(bytes_out) FROM traffic_1m`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1000 {
		t.Fatalf("duplicate bytes: %d", total)
	}
}

func TestDuplicateChecksEntireEnvelope(t *testing.T) {
	s, ag := ingestFixture(t)
	original := event("immutable", 1, "health", protocol.HealthPayload{Kind: "alive"})
	if r := apply(t, s, ag, original); r.Err != "" {
		t.Fatal(r.Err)
	}
	for _, field := range []string{"seq", "kind", "time", "body"} {
		t.Run(field, func(t *testing.T) {
			ev := original
			switch field {
			case "seq":
				ev.Seq = 2
			case "kind":
				ev.Kind = "dns"
			case "time":
				ev.ObservedAtMS++
			case "body":
				ev.Payload = json.RawMessage(`{"kind":"gap"}`)
			}
			if r := apply(t, s, ag, ev); r.Err == "" || len(r.Ack) != 0 {
				t.Fatalf("accepted conflict: %+v", r)
			}
		})
	}
	clone := ingest.Agent{ID: "b", HostID: "b", Trust: "quarantined"}
	if r := apply(t, s, clone, original); r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("clone replay: %+v", r)
	}
	var hosts int
	s.DB.QueryRow(`SELECT COUNT(*) FROM collector_health`).Scan(&hosts)
	if hosts != 1 {
		t.Fatal("clone mixed original event", hosts)
	}
	if r := apply(t, s, ag, original); r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("valid repeat: %+v", r)
	}
}

func TestAdoptFlowOnSameHost(t *testing.T) {
	s, ag := ingestFixture(t)
	if r := apply(t, s, ag, event("f1", 1, "flow", testFlow("u1"))); r.Err != "" {
		t.Fatal(r)
	}
	if err := s.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a2','a','a2','trusted',1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ag2 := ingest.Agent{ID: "a2", HostID: "a", Trust: "trusted"}
	sample := event("s1", 1, "sample", protocol.SamplePayload{FlowUID: "u1", T0MS: 1, T1MS: 2, OrigBytesDelta: 10, Quality: "ok"})
	r := apply(t, s, ag2, sample)
	if r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("%+v", r)
	}
	var owner string
	s.DB.QueryRow(`SELECT agent_id FROM flows WHERE flow_uid='u1'`).Scan(&owner)
	if owner != "a2" {
		t.Fatal("owner", owner)
	}
}

func TestDropForeignFlow(t *testing.T) {
	s, ag := ingestFixture(t)
	if r := apply(t, s, ag, event("f1", 1, "flow", testFlow("u1"))); r.Err != "" {
		t.Fatal(r)
	}
	b := ingest.Agent{ID: "b", HostID: "b", Trust: "trusted"}
	sample := event("s1", 1, "sample", protocol.SamplePayload{FlowUID: "u1", T0MS: 1, T1MS: 2, OrigBytesDelta: 10, Quality: "ok"})
	r := apply(t, s, b, sample)
	if r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("want ack drop %+v", r)
	}
	var owner string
	s.DB.QueryRow(`SELECT agent_id FROM flows WHERE flow_uid='u1'`).Scan(&owner)
	if owner != "a" {
		t.Fatal("owner", owner)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM flow_samples`).Scan(&n)
	if n != 0 {
		t.Fatal("sample written", n)
	}
}

func TestAliveHealthOneRow(t *testing.T) {
	s, ag := ingestFixture(t)
	r := apply(t, s, ag, event("h1", 1, "health", protocol.HealthPayload{Kind: "alive"}))
	if r.Err != "" {
		t.Fatal(r)
	}
	r = apply(t, s, ag, event("h2", 2, "health", protocol.HealthPayload{Kind: "alive"}))
	if r.Err != "" {
		t.Fatal(r)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM collector_health`).Scan(&n)
	if n != 1 {
		t.Fatal("alive rows", n)
	}
}

func TestRejectsInvalidEnvelopeAndPayload(t *testing.T) {
	for _, kind := range []string{"flow", "sample", "dns", "firewall", "ssh", "scan", "question", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, ag := ingestFixture(t)
			bad := event("bad", 1, kind, map[string]any{})
			if r := apply(t, s, ag, bad); r.Err == "" || len(r.Ack) != 0 {
				t.Fatalf("invalid payload: %+v", r)
			}
			fixed := event("bad", 1, "health", protocol.HealthPayload{Kind: "alive"})
			if r := apply(t, s, ag, fixed); r.Err != "" || len(r.Ack) != 1 {
				t.Fatalf("poisoned marker: %+v", r)
			}
		})
	}
	for _, field := range []string{"seq", "time", "null", "owner"} {
		t.Run(field, func(t *testing.T) {
			s, ag := ingestFixture(t)
			ev := event("bad", 1, "health", protocol.HealthPayload{Kind: "alive"})
			switch field {
			case "seq":
				ev.Seq = 0
			case "time":
				ev.ObservedAtMS = 0
			case "null":
				ev.Payload = json.RawMessage("null")
			case "owner":
				ag.HostID = "b"
			}
			if r := apply(t, s, ag, ev); r.Err == "" || len(r.Ack) != 0 {
				t.Fatalf("invalid envelope: %+v", r)
			}
		})
	}
}

func TestFlowOwnershipAndSequence(t *testing.T) {
	s, ag := ingestFixture(t)
	flow := testFlow("owned")
	if r := apply(t, s, ag, event("f1", 1, "flow", flow)); r.Err != "" {
		t.Fatal(r.Err)
	}
	other := ingest.Agent{ID: "b", HostID: "b", Trust: "trusted"}
	if r := apply(t, s, other, event("f2", 1, "flow", flow)); r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("foreign flow %+v", r)
	}
	var owner string
	s.DB.QueryRow(`SELECT agent_id FROM flows WHERE flow_uid=?`, flow.FlowUID).Scan(&owner)
	if owner != "a" {
		t.Fatal("other agent changed flow", owner)
	}
	if r := apply(t, s, other, event("s2", 2, "sample", protocol.SamplePayload{FlowUID: flow.FlowUID, T0MS: 1, T1MS: 100, OrigBytesDelta: 50})); r.Err != "" || len(r.Ack) != 1 {
		t.Fatalf("foreign sample %+v", r)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM flow_samples`).Scan(&n)
	if n != 0 {
		t.Fatal("other agent added sample")
	}
	if r := apply(t, s, ag, event("same-seq", 1, "health", protocol.HealthPayload{})); r.Err == "" {
		t.Fatal("sequence reused")
	}
	for _, seq := range []int64{10, 2} {
		if r := apply(t, s, ag, event(fmt.Sprint(seq), seq, "health", protocol.HealthPayload{})); r.Err != "" {
			t.Fatal(r.Err)
		}
	}
}
