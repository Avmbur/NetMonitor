package agent

import (
	"database/sql"
	"errors"

	"testing"
	"time"

	"netmonitor/internal/collect"

	"netmonitor/internal/store"
)

func reviewSQL(t *testing.T, st *store.Store, q string) {
	t.Helper()
	if err := st.Update(func(tx *sql.Tx) error { _, err := tx.Exec(q); return err }); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolReviewCollectorRollback(t *testing.T) {
	a, _, _ := newSpool(t)
	dumpBytes(t, a, 100, 1000)
	before := a.plan.copy()
	next := a.memSeq
	if err := failedCollector(a, 250, 16000); err == nil {
		t.Fatal("sequence failure hidden")
	}
	if len(a.plan.copy()) != len(before) || a.memSeq != next {
		t.Fatal("failed pass changed the queue or sequence")
	}
	dumpBytes(t, a, 400, 31000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 1 || ds[0] != 300 {
		t.Fatalf("checkpoint advanced on failure: deltas %v, want [300]", ds)
	}
}

func TestSpoolReviewFirstPassRollback(t *testing.T) {
	a, _, _ := newSpool(t)
	if err := failedCollector(a, 100, 1000); err == nil {
		t.Fatal("first sequence failure hidden")
	}
	if !a.book.Empty() || len(a.plan.copy()) != 0 || len(a.book.Take()) != 0 {
		t.Fatal("failed first pass left a checkpoint or events")
	}
	dumpBytes(t, a, 250, 16000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 0 {
		t.Fatalf("failed baseline used: %v", ds)
	}
	dumpBytes(t, a, 400, 31000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 1 || ds[0] != 150 {
		t.Fatalf("retry baseline: %v", ds)
	}
}

func waitSpoolReview(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("spool operation did not finish")
	}
}

func failedCollector(a *Agent, bytes, at int64) error {
	return a.collectMem(func(book *collect.Mem) error {
		e, opt := spoolObservation(bytes, at)
		if err := book.ApplyDump([]collect.Entry{e}, opt); err != nil {
			return err
		}
		return errors.New("injected collector failure")
	})
}

func TestSpoolReviewCloseWaitsForCollector(t *testing.T) {
	a, _, dir := newSpool(t)
	dumpBytes(t, a, 100, 1000)
	applied, release := make(chan struct{}), make(chan struct{})
	accepted := make(chan error, 1)
	go func() {
		accepted <- a.collectMem(func(book *collect.Mem) error {
			e, opt := spoolObservation(250, 16000)
			if err := book.ApplyDump([]collect.Entry{e}, opt); err != nil {
				return err
			}
			close(applied)
			<-release
			return nil
		})
	}()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	select {
	case err := <-closed:
		close(release)
		t.Fatalf("close passed active collector: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	waitSpoolReview(t, accepted)
	waitSpoolReview(t, closed)
	if err := dumpBytesErr(a, 999, 31000); !errors.Is(err, errSpoolClosed) {
		t.Fatalf("late collector: %v", err)
	}
	reopened, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var n int
	if err := reopened.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n); err != nil || n != 0 {
		t.Fatalf("telemetry persisted at close: %d %v", n, err)
	}
	b := &Agent{st: reopened, session: "test-session"}
	if err := b.recoverSpool(); err != nil {
		t.Fatal(err)
	}
	dumpBytes(t, b, 400, 31000)
	if ds := deltasOf(t, b.plan.copy()); len(ds) != 0 {
		t.Fatalf("restored old baseline: %v", ds)
	}
}
