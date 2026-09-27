package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	sqlite "modernc.org/sqlite"
)

type backuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

func fileDSN(path, extra string) string {
	path, err := filepath.Abs(path)
	if err != nil {
		path = filepath.Clean(path)
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if runtime.GOOS == "windows" && !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	return u.String() + extra
}

func sqliteLiteral(path string) string {
	return strings.ReplaceAll(filepath.ToSlash(path), "'", "''")
}

// BackupTo copies a consistent snapshot with the SQLite Backup API.
func (s *Store) BackupTo(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	_ = os.Remove(dst)
	conn, err := s.DB.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	err = conn.Raw(func(dc any) error {
		bck, err := dc.(backuper).NewBackup(dst)
		if err != nil {
			return err
		}
		for more := true; more; {
			more, err = bck.Step(-1)
			if err != nil {
				_ = bck.Finish()
				return err
			}
		}
		return bck.Finish()
	})
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// VacuumInto writes a compacted consistent copy. Destination must be a new file.
func (s *Store) VacuumInto(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	_ = os.Remove(dst)
	_, err := s.DB.Exec("VACUUM INTO '" + sqliteLiteral(dst) + "'")
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// Integrity opens path read-only and requires PRAGMA integrity_check = ok.
func Integrity(path string) error {
	db, err := sql.Open("sqlite", fileDSN(path, "?mode=ro"))
	if err != nil {
		return err
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&v); err != nil {
		return err
	}
	if v != "ok" {
		return fmt.Errorf("integrity_check: %s", v)
	}
	return nil
}

// QueryOpen opens a snapshot read-only for checks. Caller closes it.
func QueryOpen(path string) (*sql.DB, error) {
	return sql.Open("sqlite", fileDSN(path, "?mode=ro"))
}
