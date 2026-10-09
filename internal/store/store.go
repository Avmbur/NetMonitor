package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"netmonitor/internal/schema"

	_ "modernc.org/sqlite"
)

// Журнал агента сливается каждые 128 страниц. Монитор реже: см. monitorWALPages.
// journal_size_limit 16 МБ — потолок файла журнала после сброса, не порог слива.
const dsnBase = "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)&_pragma=journal_size_limit(16777216)&_txlock=immediate"

const agentWALPages = 128

// Около 8 МБ при странице 4 КБ. Ниже предела журнала 16 МБ и запаса 32 МБ в monitorWriteLimit.
const monitorWALPages = 2000

func openDSN(kind string) string {
	pages := agentWALPages
	if kind == "monitor" {
		pages = monitorWALPages
	}
	return dsnBase + fmt.Sprintf("&_pragma=wal_autocheckpoint(%d)", pages)
}

var ErrClosed = errors.New("store is closed")

// All handles for one database share its pool and writer in this process.
// BEGIN IMMEDIATE also serializes transactions from a separate CLI process.
var stores = struct {
	sync.Mutex
	byPath map[string]*owner
}{byPath: make(map[string]*owner)}

type Store struct {
	DB     *sql.DB
	path   string
	key    string
	o      *owner
	mu     sync.RWMutex
	closed bool
}

type owner struct {
	path string
	db   *sql.DB
	conn *sql.Conn
	refs int
	kind string
	jobs chan job
	wg   sync.WaitGroup
}

type job struct {
	fn   func(*sql.Tx) error
	raw  string
	done chan error
	ctx  context.Context
}

func OpenMonitor(dir string) (*Store, error) {
	return open(filepath.Join(dir, "netmon.sqlite"), "monitor", schema.ApplyMonitor)
}

func OpenAgent(dir string) (*Store, error) {
	return open(filepath.Join(dir, "agent.sqlite"), "agent", schema.ApplyAgent)
}

func open(path, kind string, migrate func(*sql.DB) error) (*Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	path = filepath.Join(dir, filepath.Base(path))
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := path
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	stores.Lock()
	defer stores.Unlock()
	if o := stores.byPath[key]; o != nil {
		if o.kind != kind {
			return nil, fmt.Errorf("database kind: %s, expected %s", o.kind, kind)
		}
		o.refs++
		return &Store{DB: o.db, path: path, key: key, o: o}, nil
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if runtime.GOOS == "windows" && !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	db, err := sql.Open("sqlite", u.String()+openDSN(kind))
	if err != nil {
		return nil, err
	}
	// Писатель навсегда держит одно соединение. Чтения монитора местами
	// вложены (курсор открыт, внутри ещё запрос): при тесном пуле несколько
	// опросов морды забирали все соединения и ждали друг друга, а с ними
	// вставали запись и агенты. Пул монитора с запасом; число одновременных
	// опросов морды ограничено в server (uiReadSlots).
	if kind == "monitor" {
		db.SetMaxOpenConns(64)
	} else {
		db.SetMaxOpenConns(4)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if kind == "agent" {
		if _, err := db.Exec("PRAGMA max_page_count=65536"); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	o := &owner{path: path, db: db, conn: conn, refs: 1, kind: kind, jobs: make(chan job, 64)}
	if kind == "monitor" {
		if err := o.prepareRotation(); err != nil {
			_ = conn.Close()
			_ = db.Close()
			return nil, err
		}
	}
	stores.byPath[key] = o
	o.wg.Add(1)
	go o.writer()
	return &Store{DB: db, path: path, key: key, o: o}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	stores.Lock()
	defer stores.Unlock()
	s.o.refs--
	if s.o.refs != 0 {
		return nil
	}
	close(s.o.jobs)
	s.o.wg.Wait()
	err := s.o.conn.Close()
	err = errors.Join(err, s.o.db.Close())
	delete(stores.byPath, s.key)
	return err
}

func (s *Store) Path() string { return s.path }

func (s *owner) writer() {
	defer s.wg.Done()
	for j := range s.jobs {
		if err := j.ctx.Err(); err != nil {
			j.done <- err
			continue
		}
		if s.kind == "monitor" {
			if err := s.monitorWriteLimit(); err != nil {
				j.done <- err
				continue
			}
		}
		// A blocked reader must not let the agent WAL grow without bound.
		if s.kind == "agent" {
			if info, err := os.Stat(s.path + "-wal"); err == nil && info.Size() > 32<<20 {
				_, _ = s.conn.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
				if info, err = os.Stat(s.path + "-wal"); err == nil && info.Size() > 32<<20 {
					j.done <- fmt.Errorf("agent WAL limit reached; checkpoint blocked by reader")
					continue
				}
			}
		}
		// Own cancellation and rollback here. database/sql must not discard
		// the dedicated connection asynchronously on a request cancellation.
		if j.raw != "" {
			_, err := s.conn.ExecContext(context.Background(), j.raw)
			if s.kind == "monitor" && err == nil {
				_ = s.monitorWriteLimit()
			}
			j.done <- err
			continue
		}
		if s.kind == "monitor" {
			if _, err := s.conn.ExecContext(context.Background(), "DELETE FROM temp.rotation_touched"); err != nil {
				j.done <- err
				continue
			}
		}
		tx, err := s.conn.BeginTx(context.Background(), nil)
		if err != nil {
			j.done <- err
			continue
		}
		err = j.ctx.Err()
		if err == nil {
			err = j.fn(tx)
		}
		if err == nil && s.kind == "monitor" {
			err = rotateHistory(j.ctx, tx)
		}
		if err == nil {
			err = j.ctx.Err()
		}
		if err != nil {
			err = errors.Join(err, tx.Rollback())
			finishTransaction(tx, false)
			if s.kind == "monitor" {
				_ = s.monitorWriteLimit()
			}
			j.done <- err
			continue
		}
		err = tx.Commit()
		if err != nil {
			// SQLite can leave a transaction open after a failed COMMIT
			// (e.g. a deferred foreign-key constraint). sql.Tx is already
			// done, so Rollback on it cannot release that transaction.
			_, _ = s.conn.ExecContext(context.Background(), "ROLLBACK")
		}
		finishTransaction(tx, err == nil)
		if s.kind == "monitor" && err == nil {
			_ = s.monitorWriteLimit()
		}
		j.done <- err
	}
}

func (s *Store) Update(fn func(*sql.Tx) error) error {
	return s.UpdateCtx(context.Background(), fn)
}

func (s *Store) UpdateCtx(ctx context.Context, fn func(*sql.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j := job{fn: fn, done: make(chan error, 1), ctx: ctx}
	select {
	case s.o.jobs <- j:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Once queued, report the transaction's actual outcome, never an early
	// cancellation followed by a write that the caller believes failed.
	return <-j.done
}

func (s *Store) ExecDirect(q string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	j := job{raw: q, done: make(chan error, 1), ctx: context.Background()}
	s.o.jobs <- j
	return <-j.done
}

func NowMS() int64 { return time.Now().UTC().UnixMilli() }

func Setting(tx *sql.Tx, k string) (string, error) {
	var v string
	err := tx.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v, err
}

func PutSetting(tx *sql.Tx, k, v string) error {
	_, err := tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func SettingDB(db *sql.DB, k string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v, err
}
