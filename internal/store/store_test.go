package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netmonitor/internal/store"
)

func TestSharedWriterAndClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db # with spaces")
	a, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := store.OpenMonitor(filepath.Join(dir, "."))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 0 {
				s = b
			}
			if err := s.Update(func(tx *sql.Tx) error {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				time.Sleep(time.Millisecond)
				_, err := tx.Exec(`INSERT INTO settings(k,v) VALUES('count','1') ON CONFLICT(k) DO UPDATE SET v=CAST(v AS INTEGER)+1`)
				return err
			}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("concurrent writer callbacks: %d", peak.Load())
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Update(func(*sql.Tx) error { t.Error("closed handle executed"); return nil }); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("closed update: %v", err)
	}
	v, err := store.SettingDB(b.DB, "count")
	if err != nil || v != "24" {
		t.Fatalf("count=%s err=%v", v, err)
	}
	if err := b.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "alive", "yes") }); err != nil {
		t.Fatal(err)
	}
}

func TestPragmasOnEveryConnection(t *testing.T) {
	s, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var conns []*sql.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := s.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		for pragma, want := range map[string]string{"journal_mode": "wal", "synchronous": "2", "foreign_keys": "1", "busy_timeout": "5000"} {
			var got string
			if err := c.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("connection %d %s=%s want %s", i, pragma, got, want)
			}
		}
	}
}

func TestCancelledQueueDoesNotWriteLater(t *testing.T) {
	s, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entered, release, first := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() { first <- s.Update(func(*sql.Tx) error { close(entered); <-release; return nil }) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		second <- s.UpdateCtx(ctx, func(tx *sql.Tx) error { return store.PutSetting(tx, "cancelled", "bad") })
	}()
	cancel()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := store.SettingDB(s.DB, "cancelled"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cancelled write survived: %v", err)
	}
}

func TestCrashTransaction(t *testing.T) {
	if mode := os.Getenv("NM_STORE_CRASH"); mode != "" {
		s, err := store.OpenMonitor(os.Getenv("NM_STORE_DIR"))
		if err != nil {
			t.Fatal(err)
		}
		err = s.Update(func(tx *sql.Tx) error {
			if err := store.PutSetting(tx, "durable", mode); err != nil {
				return err
			}
			if mode == "before" {
				os.Exit(23)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		os.Exit(23) // after COMMIT, without Close or WAL checkpoint
	}
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashTransaction$")
			cmd.Env = append(os.Environ(), "NM_STORE_CRASH="+mode, "NM_STORE_DIR="+dir)
			out, err := cmd.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 23 {
				t.Fatalf("crash: %v %s", err, out)
			}
			s, err := store.OpenMonitor(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			v, err := store.SettingDB(s.DB, "durable")
			if mode == "before" && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("uncommitted record survived: %q %v", v, err)
			}
			if mode == "after" && (err != nil || v != "after") {
				t.Fatalf("committed record lost: %q %v", v, err)
			}
		})
	}
}

func TestCancellationDuringWriteRollsBackAndWriterRecovers(t *testing.T) {
	s, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err = s.UpdateCtx(ctx, func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "cancelled", "bad"); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := store.SettingDB(s.DB, "cancelled"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cancelled write survived: %v", err)
	}
	if err := s.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "next", "ok") }); err != nil {
		t.Fatal(err)
	}
}

func TestCLIWriterProcess(t *testing.T) {
	if dir := os.Getenv("NM_STORE_CLI_DIR"); dir != "" {
		s, err := store.OpenMonitor(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		for i := 0; i < 30; i++ {
			if err := s.Update(func(tx *sql.Tx) error {
				v, err := store.Setting(tx, "count")
				if err != nil {
					return err
				}
				return store.PutSetting(tx, "count", v+"x")
			}); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	dir := t.TempDir()
	s, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "count", "") }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestCLIWriterProcess$")
			cmd.Env = append(os.Environ(), "NM_STORE_CLI_DIR="+dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("CLI writer: %v %s", err, out)
			}
		}()
	}
	for i := 0; i < 30; i++ {
		if err := s.Update(func(tx *sql.Tx) error {
			v, err := store.Setting(tx, "count")
			if err != nil {
				return err
			}
			return store.PutSetting(tx, "count", v+"x")
		}); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
	v, err := store.SettingDB(s.DB, "count")
	if err != nil || len(v) != 90 {
		t.Fatalf("lost concurrent updates: count=%d err=%v", len(v), err)
	}
}

func TestCopiedDatabaseMigration(t *testing.T) {
	dir := os.Getenv("NM_MIGRATION_DIR")
	if dir == "" {
		t.Skip("set NM_MIGRATION_DIR to an isolated copy of a monitor or agent database")
	}
	kind := os.Getenv("NM_MIGRATION_KIND")
	name, open := "netmon.sqlite", store.OpenMonitor
	if kind == "agent" {
		name, open = "agent.sqlite", store.OpenAgent
	} else if kind != "monitor" {
		t.Fatal("NM_MIGRATION_KIND must be monitor or agent")
	}
	raw, err := sql.Open("sqlite", filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	type counts map[string]int64
	count := func(db *sql.DB) counts {
		t.Helper()
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		values := make(counts)
		for _, name := range names {
			var n int64
			if err := db.QueryRow("SELECT COUNT(*) FROM " + name).Scan(&n); err != nil {
				t.Fatal(err)
			}
			values[name] = n
		}
		return values
	}
	before := count(raw)
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s, err := open(dir)
		if err != nil {
			t.Fatal(err)
		}
		after := count(s.DB)
		for name, n := range before {
			if after[name] != n {
				t.Errorf("%s: before=%d after=%d", name, n, after[name])
			}
		}
		var check string
		if err := s.DB.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
			t.Fatalf("integrity: %s %v", check, err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%s: %d tables retain their row counts; repeated migration and integrity_check OK", kind, len(before))
}
