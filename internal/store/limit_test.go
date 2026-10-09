package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
)

func TestWALAutocheckpoint(t *testing.T) {
	mon, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	var pages int
	if err := mon.DB.QueryRow("PRAGMA wal_autocheckpoint").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != monitorWALPages {
		t.Fatalf("monitor wal_autocheckpoint=%d", pages)
	}
	ag, err := OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	if err := ag.DB.QueryRow("PRAGMA wal_autocheckpoint").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != agentWALPages {
		t.Fatalf("agent wal_autocheckpoint=%d", pages)
	}
}

func TestMonitorFileLimitAndRecovery(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const limit = 1 << 20
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", strconv.Itoa(limit)); err != nil {
			return err
		}
		_, err := tx.Exec("CREATE TABLE bulk(id INTEGER PRIMARY KEY,payload TEXT)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rejected := false
	for i := 0; i < 100; i++ {
		err := st.Update(func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO bulk(payload) VALUES(?)", strings.Repeat("x", 32768))
			return err
		})
		if err != nil {
			if !strings.Contains(err.Error(), "full") {
				t.Fatal(err)
			}
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("SQLite did not enforce its allocation limit")
	}
	size := sqliteFileBytes(st.Path()) + sqliteFileBytes(st.Path()+"-wal")
	if size > limit {
		t.Fatalf("main+WAL=%d > %d", size, limit)
	}
	if err := st.Update(func(tx *sql.Tx) error { _, err := tx.Exec("DELETE FROM bulk"); return err }); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error { _, err := tx.Exec("INSERT INTO bulk(payload) VALUES('recovered')"); return err }); err != nil {
		t.Fatal(err)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
	t.Logf("allocation stopped at main+WAL=%d, limit=%d; writes recovered after cleanup", size, limit)
}

func TestMonitorWALBoundAndRecovery(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", strconv.Itoa(2<<20)); err != nil {
			return err
		}
		return PutSetting(tx, "bulk", "small")
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ExecDirect("PRAGMA busy_timeout=20"); err != nil {
		t.Fatal(err)
	}
	reader, err := st.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ExecContext(context.Background(), "BEGIN DEFERRED"); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := reader.QueryRowContext(context.Background(), "SELECT v FROM settings WHERE k='bulk'").Scan(&value); err != nil {
		t.Fatal(err)
	}
	failed := false
	for i := 0; i < 12; i++ {
		err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "bulk", strings.Repeat(string(rune('a'+i)), 65536)) })
		if err != nil {
			if !strings.Contains(err.Error(), "WAL limit") {
				t.Fatal(err)
			}
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("pinned WAL kept growing")
	}
	size := sqliteFileBytes(st.Path() + "-wal")
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "bulk", "must wait") }); err == nil {
		t.Fatal("write accepted while WAL blocked")
	}
	if again := sqliteFileBytes(st.Path() + "-wal"); again != size {
		t.Fatalf("blocked WAL grew: %d -> %d", size, again)
	}
	if _, err := reader.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "bulk", "recovered") }); err != nil {
		t.Fatal(err)
	}
}
