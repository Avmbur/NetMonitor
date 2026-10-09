package agent

import (
	"database/sql"
	"netmonitor/internal/collect"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestReviewSessionFlushIncludesMemory(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	got := serveBatches(t, a, nil)
	if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "alive"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("Flush sent %d events, want 1", len(*got))
	}
}

func TestReviewSessionNeverPersistsCheckpoints(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	dumpBytes(t, a, 100, 1000)
	if n := countSQL(t, st.DB, "SELECT COUNT(*) FROM checkpoints"); n != 0 {
		t.Fatalf("persisted %d traffic checkpoints", n)
	}
}

func TestReviewVolatileBeforeHandshake(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.session = ""
	dumpBytes(t, a, 100, 1000)
	if err := a.Enqueue("ssh", 9, protocol.SSHPayload{RemoteIP: "203.0.113.50"}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"outbox", "checkpoints"} {
		if n := countSQL(t, st.DB, "SELECT COUNT(*) FROM "+table); n != 0 {
			t.Fatalf("%s: %d", table, n)
		}
	}
}

func TestReviewSessionMixedFailureIsAtomic(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	if err := st.Update(func(tx *sql.Tx) error {
		_, e := tx.Exec("CREATE TRIGGER fail_queue BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fail'); END")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	err := a.acceptMem([]collect.MemEvent{
		{Kind: "health", Pri: 10, Payload: protocol.HealthPayload{Kind: "alive"}, Now: 1000},
		{Kind: "question", Pri: 7, Payload: protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443}, Now: 1000},
	})
	if err == nil {
		t.Fatal("wanted durable failure")
	}
	if n := len(a.plan.copy()); n != 0 {
		t.Fatalf("failed mixed batch published %d events", n)
	}
}

func TestReviewSessionSSHCollectorStaysInMemory(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	if err := a.saveSSH([]collect.SSHFail{{IP: "203.0.113.50", AtMS: store.NowMS()}}, "cursor-1"); err != nil {
		t.Fatal(err)
	}
	if n := countSQL(t, st.DB, "SELECT COUNT(*) FROM outbox WHERE kind='ssh'"); n != 0 {
		t.Fatalf("SSH collector wrote %d disk events", n)
	}
	if n := len(a.plan.copy()); n != 1 {
		t.Fatalf("SSH collector queued %d memory events", n)
	}
	if cur := metaVal(t, st.DB, "ssh_cursor"); cur != "" {
		t.Fatalf("persisted cursor %q", cur)
	}
}

func TestReviewSessionConntrackHealthStaysInMemory(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	if err := a.saveConntrackStats(map[string]uint64{"drop": 2}); err != nil {
		t.Fatal(err)
	}
	if err := a.saveConntrackStats(map[string]uint64{"drop": 5}); err != nil {
		t.Fatal(err)
	}
	if n := len(a.plan.copy()); n != 1 {
		t.Fatalf("gap notifications %d", n)
	}
	if n := countSQL(t, st.DB, "SELECT COUNT(*) FROM outbox"); n != 0 {
		t.Fatal(n)
	}
	if n := countSQL(t, st.DB, "SELECT COUNT(*) FROM meta WHERE k LIKE 'ct_failures:%'"); n != 0 {
		t.Fatalf("saved %d counter snapshots", n)
	}
}
func TestReviewSessionSSHSkipsEarlierJournal(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	if err := a.saveSSH([]collect.SSHFail{{IP: "203.0.113.50", AtMS: a.telemetrySince - 1}}, "old"); err != nil {
		t.Fatal(err)
	}
	if n := len(a.plan.copy()); n != 0 {
		t.Fatalf("replayed %d pre-start SSH failures", n)
	}
	if a.sshCursor != "old" {
		t.Fatal("cursor did not advance")
	}
}

func TestReviewSessionQuestionPrecedesTelemetryFlood(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s")
	got := serveBatches(t, a, nil)
	for i := 0; i < 210; i++ {
		if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_gap"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Enqueue("question", 7, protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.50", RemotePort: 443}); err != nil {
		t.Fatal(err)
	}
	if err := a.flushLane("urgent"); err != nil {
		t.Fatal(err)
	}
	for _, ev := range *got {
		if ev.Kind == "question" {
			return
		}
	}
	t.Fatal("telemetry filled the batch and starved the durable question")
}
