package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
)

type capQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func MonitorCapBytes(q capQuery) (int64, error) {
	var raw, gb string
	if err := q.QueryRowContext(context.Background(), `SELECT
  COALESCE((SELECT v FROM settings WHERE k='db_max_bytes'),''),
  COALESCE((SELECT v FROM settings WHERE k='db_max_gb'),'2')`).Scan(&raw, &gb); err != nil {
		return 0, err
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
		return n, nil
	}
	n, err := strconv.ParseInt(gb, 10, 64)
	if err != nil || n < 1 {
		n = 2
	}
	if n > 99 {
		n = 99
	}
	return n << 30, nil
}

func sqliteFileBytes(path string) int64 {
	s, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return s.Size()
}

// Allow bounded transaction workspace; rotateHistory enforces the configured
// page limit before COMMIT.
// A long reader cannot allow successive writes to grow WAL without a bound.
func (s *owner) monitorWriteLimit() error {
	max, err := MonitorCapBytes(s.conn)
	if err != nil {
		return err
	}
	reserve := max / 16
	if reserve > 32<<20 {
		reserve = 32 << 20
	}
	var pageSize int64
	if err := s.conn.QueryRowContext(context.Background(), "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	pages := (max + (32 << 20)) / pageSize
	if pages < 1 {
		pages = 1
	}
	var actual int64
	if err := s.conn.QueryRowContext(context.Background(), fmt.Sprintf("PRAGMA max_page_count=%d", pages)).Scan(&actual); err != nil {
		return err
	}
	wal := sqliteFileBytes(s.path + "-wal")
	if wal > reserve || sqliteFileBytes(s.path)+wal > max {
		var busy, log, done int
		if err := s.conn.QueryRowContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
			return err
		}
		if busy != 0 && sqliteFileBytes(s.path+"-wal") > reserve {
			return fmt.Errorf("monitor WAL limit: checkpoint blocked by reader")
		}
	}
	return nil
}
