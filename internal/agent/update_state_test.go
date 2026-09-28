package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"netmonitor/internal/protocol"
)

func TestUpdateWaitsForFinalVerdict(t *testing.T) {
	for _, current := range []string{"1.0", "1.1"} {
		t.Run(current, func(t *testing.T) {
			dir := t.TempDir()
			state := &agentUpdateState{CommandID: "c1", Version: "1.1"}
			if err := saveUpdateState(dir, state); err != nil {
				t.Fatal(err)
			}
			reports := 0
			report := func(protocol.UpdateResult) error { reports++; return nil }
			active := func(string) (bool, error) { return true, nil }
			for range 3 {
				done, err := reconcileUpdate(dir, current, "", active, report)
				if err != nil || done || reports != 0 {
					t.Fatal("premature result", done, err, reports)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "update.outcome"), []byte("rolledback\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var result protocol.UpdateResult
			_, err := reconcileUpdate(dir, "1.0", "", active, func(r protocol.UpdateResult) error { result = r; return nil })
			if err != nil || result.Phase != "failed" {
				t.Fatal(result, err)
			}
		})
	}
}

func TestUpdateResultSurvivesLostResponseAndRestart(t *testing.T) {
	for _, outcome := range []string{"verified", "rolledback", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			dir := t.TempDir()
			if err := saveUpdateState(dir, &agentUpdateState{CommandID: "c1", Version: "1.1"}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "update.outcome"), []byte(outcome), 0600); err != nil {
				t.Fatal(err)
			}
			active := func(string) (bool, error) { t.Fatal("terminal verdict queried unit"); return false, nil }
			var first protocol.UpdateResult
			_, err := reconcileUpdate(dir, "1.1", "", active, func(r protocol.UpdateResult) error { first = r; return errors.New("response lost") })
			if err == nil {
				t.Fatal("network failure hidden")
			}
			state, err := readUpdateState(dir)
			if err != nil || state.Acked || state.Phase != first.Phase {
				t.Fatal(state, err)
			}
			// Recreate the sender and even change the current version: replay the saved result.
			if err := os.Remove(filepath.Join(dir, "update.outcome")); err != nil {
				t.Fatal(err)
			}
			var second protocol.UpdateResult
			done, err := reconcileUpdate(dir, "0.9", "", active, func(r protocol.UpdateResult) error { second = r; return nil })
			if err != nil || !done || first != second {
				t.Fatal(first, second, done, err)
			}
			state, err = readUpdateState(dir)
			if err != nil || !state.Acked {
				t.Fatal(state, err)
			}
			// Keep the acknowledged marker so late redelivery cannot reinstall this command.
			_, err = reconcileUpdate(dir, "0.9", "", active, func(protocol.UpdateResult) error { t.Fatal("acknowledged result resent"); return nil })
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpdateSameProcessAndInterruptedWorker(t *testing.T) {
	dir := t.TempDir()
	if err := saveUpdateState(dir, &agentUpdateState{CommandID: "c1", Version: "1.1"}); err != nil {
		t.Fatal(err)
	}
	_, err := reconcileUpdate(dir, "1.0", "c1", func(string) (bool, error) { t.Fatal("initiator treated as restarted agent"); return false, nil }, func(protocol.UpdateResult) error { t.Fatal("premature version mismatch"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var got protocol.UpdateResult
	_, err = reconcileUpdate(dir, "1.1", "", func(string) (bool, error) { return false, nil }, func(r protocol.UpdateResult) error { got = r; return nil })
	if err != nil || got.Phase != "failed" {
		t.Fatal(got, err)
	}
}

func TestUpdateVerifiedWrongVersionRemainsFailed(t *testing.T) {
	dir := t.TempDir()
	if err := saveUpdateState(dir, &agentUpdateState{CommandID: "c1", Version: "1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "update.outcome"), []byte("verified"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, err := reconcileUpdate(dir, "1.0", "", nil, func(r protocol.UpdateResult) error {
			if r.Phase != "failed" {
				t.Fatal("wrong version accepted", r)
			}
			return errors.New("offline")
		})
		if err == nil {
			t.Fatal("offline ignored")
		}
	}
}
