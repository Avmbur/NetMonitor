package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestAgentWALBoundAndRecovery(t *testing.T) {
	st, err := OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("INSERT INTO meta(k,v) VALUES('bulk','small')"); return e }); err != nil {
		t.Fatal(err)
	}
	reader, err := st.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.ExecContext(context.Background(), "BEGIN DEFERRED"); err != nil {
		t.Fatal(err)
	}
	var v string
	if err = reader.QueryRowContext(context.Background(), "SELECT v FROM meta WHERE k='bulk'").Scan(&v); err != nil {
		t.Fatal(err)
	}
	failed := false
	for i := 0; i < 7; i++ {
		value := strings.Repeat(string(rune('a'+i)), 8<<20)
		err = st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("UPDATE meta SET v=? WHERE k='bulk'", value); return e })
		if err != nil {
			if !strings.Contains(err.Error(), "WAL limit") {
				t.Fatal(err)
			}
			failed = true
			break
		}
	}
	if !failed {
		t.Fatal("WAL grew past bound")
	}
	if _, err = reader.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if err = st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("UPDATE meta SET v='recovered' WHERE k='bulk'"); return e }); err != nil {
		t.Fatal(err)
	}
	if err = st.DB.QueryRow("SELECT v FROM meta WHERE k='bulk'").Scan(&v); err != nil || v != "recovered" {
		t.Fatal("did not recover", err)
	}
}
