package store

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
)

func TestBackupContainsCommittedRowDuringWrites(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		return PutSetting(tx, "marker", "before")
	}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "snap.sqlite")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = st.Update(func(tx *sql.Tx) error {
				return PutSetting(tx, "n", "x")
			})
		}
	}()
	if err := st.BackupTo(dst); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
	if err := Integrity(dst); err != nil {
		t.Fatal(err)
	}
	db, err := QueryOpen(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT v FROM settings WHERE k='marker'").Scan(&v); err != nil || v != "before" {
		t.Fatal(v, err)
	}
}

func TestVacuumIntoIsIndependentFile(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		return PutSetting(tx, "keep", "yes")
	}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "compact.sqlite")
	if err := st.VacuumInto(dst); err != nil {
		t.Fatal(err)
	}
	if err := Integrity(dst); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error {
		return PutSetting(tx, "keep", "changed")
	}); err != nil {
		t.Fatal(err)
	}
	db, err := QueryOpen(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT v FROM settings WHERE k='keep'").Scan(&v); err != nil || v != "yes" {
		t.Fatal(v, err)
	}
}
