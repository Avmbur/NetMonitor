package server

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/collect"
	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
)

var diskSizeFn = diskSize

var errDbCap = store.ErrDatabaseFull

func (s *Server) dataDir() string {
	if s.cfg.DataDir != "" {
		return s.cfg.DataDir
	}
	return filepath.Dir(s.st.Path())
}

func (s *Server) snapDir() string {
	return filepath.Join(s.dataDir(), "snapshots")
}

func (s *Server) parkLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.parkOnce()
		}
	}
}

func (s *Server) parkOnce() {
	if err := s.refreshDisk(); err != nil {
		log.Printf("disk: %v", err)
	}
	if err := s.retainNow(store.NowMS()); err != nil {
		log.Printf("retain: %v", err)
	}
	if err := s.enforceDbCap(); err != nil {
		log.Printf("db cap: %v", err)
	}
	if err := s.dailySnapshot(); err != nil {
		log.Printf("daily snapshot: %v", err)
	}
}

func diskPercent(path string) (int, error) {
	total, free, err := diskSizeFn(path)
	if err != nil || total == 0 {
		return 0, err
	}
	return int((total - free) * 100 / total), nil
}

func (s *Server) refreshDisk() error {
	pct, err := diskPercent(s.dataDir())
	if err != nil {
		return err
	}
	skip := "0"
	if pct >= 90 {
		skip = "1"
	}
	return s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "disk_pct", strconv.Itoa(pct)); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "disk_skip_samples", skip); err != nil {
			return err
		}
		now := store.NowMS()
		if pct < 90 {
			if _, err := tx.Exec(`UPDATE alerts SET closed_at_ms=? WHERE rule_id='disk-90' AND closed_at_ms IS NULL`, now); err != nil {
				return err
			}
		}
		if pct < 80 {
			if _, err := tx.Exec(`UPDATE alerts SET closed_at_ms=? WHERE rule_id='disk-80' AND closed_at_ms IS NULL`, now); err != nil {
				return err
			}
		}
		if pct >= 90 {
			return raiseAlert(tx, "monitor", "disk-90", "диск 90% — трафик не пишется", now)
		}
		if pct >= 80 {
			return raiseAlert(tx, "monitor", "disk-80", "диск 80% — мало места", now)
		}
		return nil
	})
}

func (s *Server) takeSnapshot() (string, error) {
	name := time.Now().UTC().Format("netmon-20060102-150405") + "-" + idgen.NewV7() + ".sqlite"
	dest := filepath.Join(s.snapDir(), name)
	if err := s.st.BackupTo(dest); err != nil {
		return "", err
	}
	if err := store.Integrity(dest); err != nil {
		_ = os.Remove(dest)
		return "", err
	}
	label := time.Now().Format("02.01.2006 15:04")
	if err := s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "snap_at", label); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)",
			idgen.NewV7(), store.NowMS(), "adm", "снял снимок БД", name)
		return err
	}); err != nil {
		return "", err
	}
	if err := s.keepOnlySnapshot(dest); err != nil {
		return "", err
	}
	return dest, nil
}

func (s *Server) dailySnapshot() error {
	day := time.Now().UTC().Format("20060102")
	last, _ := store.SettingDB(s.st.DB, "daily_snap")
	if last == day {
		return s.keepOnlySnapshot("")
	}
	if err := s.st.ExecDirect("VACUUM"); err != nil {
		log.Printf("vacuum: %v", err)
	}
	dest := filepath.Join(s.snapDir(), "netmon-"+day+".sqlite")
	if err := s.st.VacuumInto(dest); err != nil {
		return err
	}
	if err := store.Integrity(dest); err != nil {
		_ = os.Remove(dest)
		return err
	}
	label := time.Now().Format("02.01.2006 15:04")
	if err := s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "daily_snap", day); err != nil {
			return err
		}
		return store.PutSetting(tx, "snap_at", label)
	}); err != nil {
		return err
	}
	return s.keepOnlySnapshot(dest)
}

func (s *Server) keepOnlySnapshot(keep string) error {
	matches, err := filepath.Glob(filepath.Join(s.snapDir(), "netmon-*.sqlite"))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	if keep == "" && len(matches) > 0 {
		keep = matches[len(matches)-1]
	}
	keep, _ = filepath.Abs(keep)
	for _, p := range matches {
		abs, _ := filepath.Abs(p)
		if abs == keep {
			continue
		}
		_ = os.Remove(p)
	}
	return nil
}

func keepSpan(db *sql.DB, kind string, defN int, defU string) int64 {
	n := defN
	u := defU
	if v, err := store.SettingDB(db, kind+"_n"); err == nil {
		if x, e := strconv.Atoi(v); e == nil && x > 0 {
			n = x
		}
	}
	if v, err := store.SettingDB(db, kind+"_u"); err == nil && (v == "d" || v == "mo") {
		u = v
	}
	day := int64(86400000)
	if u == "mo" {
		return int64(n) * 30 * day
	}
	return int64(n) * day
}

func (s *Server) retainNow(now int64) error {
	sampleCut := now - keepSpan(s.st.DB, "samples", 30, "d")
	flowCut := now - keepSpan(s.st.DB, "flows", 90, "d")
	hourCut := now - keepSpan(s.st.DB, "hours", 12, "mo")
	healthCut := now - 14*int64(86400000)
	return s.st.Update(func(tx *sql.Tx) error {
		if err := deleteOld(tx, `DELETE FROM flow_samples WHERE rowid IN (SELECT rowid FROM flow_samples WHERE t0_ms<? LIMIT 500)`, sampleCut); err != nil {
			return err
		}
		if err := deleteOld(tx, `DELETE FROM firewall_events WHERE rowid IN (SELECT rowid FROM firewall_events WHERE observed_at_ms<? LIMIT 500)`, flowCut); err != nil {
			return err
		}
		if err := deleteOld(tx, `DELETE FROM flows WHERE rowid IN (
			SELECT rowid FROM flows WHERE last_seen_at_ms<? AND ended_at_ms IS NOT NULL
			AND flow_uid NOT IN (SELECT flow_uid FROM flow_samples) LIMIT 500)`, flowCut); err != nil {
			return err
		}
		if err := deleteOld(tx, `DELETE FROM traffic_1m WHERE bucket_start_ms<?`, sampleCut); err != nil {
			return err
		}
		if err := deleteOld(tx, `DELETE FROM traffic_1h WHERE bucket_start_ms<?`, hourCut); err != nil {
			return err
		}
		if _, err := deleteConfirmedReceipts(tx); err != nil {
			return err
		}
		if err := deleteOld(tx, `DELETE FROM collector_health WHERE rowid IN (SELECT rowid FROM collector_health WHERE kind!='alive' AND observed_at_ms<? LIMIT 500)`, healthCut); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM collector_health WHERE kind='alive' AND rowid NOT IN (
			SELECT MAX(rowid) FROM collector_health WHERE kind='alive' GROUP BY agent_id)`)
		return err
	})
}

func dbCapBytes(db *sql.DB) int64 {
	n, err := store.MonitorCapBytes(db)
	if err != nil {
		return 2 << 30
	}
	return n
}

func (s *Server) dbFileBytes() int64 {
	return fileSize(s.st.Path()) + fileSize(s.st.Path()+"-wal")
}

func (s *Server) enforceDbCap() error {
	// The shared writer also runs this rotation on every incoming transaction.
	if err := s.st.Update(func(tx *sql.Tx) error { return nil }); err != nil {
		return err
	}
	return s.st.ExecDirect("PRAGMA wal_checkpoint(TRUNCATE)")
}

func deleteLimited(tx *sql.Tx, q string, args ...any) (int64, error) {
	res, err := tx.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func deleteOld(tx *sql.Tx, q string, cut int64) error {
	for {
		res, err := tx.Exec(q, cut)
		if err != nil {
			if !strings.Contains(q, "LIMIT") {
				_, err = tx.Exec(strings.Replace(q, " LIMIT 500", "", 1), cut)
				return err
			}
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		if !strings.Contains(q, "LIMIT") {
			return nil
		}
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (s *Server) fillMonitor(st *uiState) {
	st.Monitor["uptime_ms"] = store.NowMS() - s.startedMS
	st.Monitor["db_bytes"] = fileSize(s.st.Path()) + fileSize(s.st.Path()+"-wal")
	if pct, err := diskPercent(s.dataDir()); err == nil {
		st.Monitor["disk_pct"] = pct
	} else if v, err := store.SettingDB(s.st.DB, "disk_pct"); err == nil {
		if n, e := strconv.Atoi(v); e == nil {
			st.Monitor["disk_pct"] = n
		}
	}
	if res := collect.HostResources(); res.OK {
		st.Monitor["cpu_pct"] = res.CPU
		st.Monitor["ram_pct"] = res.RAM
	}
	if label, err := store.SettingDB(s.st.DB, "snap_at"); err == nil && label != "" {
		st.Monitor["archive"] = label
	}
	var q int
	_ = s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE acked_at_ms IS NULL`).Scan(&q)
	st.Monitor["queue"] = q
}

func deleteConfirmedReceipts(tx *sql.Tx) (int64, error) {
	return deleteLimited(tx, `DELETE FROM ingest_events WHERE seq<(SELECT pending_from FROM agents WHERE agents.agent_id=ingest_events.agent_id)`)
}
