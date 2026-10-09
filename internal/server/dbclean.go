package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Ниже этого объёма очистка не опускается: там остаются настройки и работа системы.
const dbCleanFloor = 64 << 20

type dbCleanResult struct {
	Now     int64  `json:"now"`
	After   int64  `json:"after,omitempty"`
	FloorMB int    `json:"floor_mb"`
	KeepMB  int    `json:"keep_mb,omitempty"`
	Reached bool   `json:"reached"`
	Detail  string `json:"detail,omitempty"`
}

func (s *Server) handleDBClean(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Confirm bool `json:"confirm"`
		KeepMB  int  `json:"keep_mb"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil && err != io.EOF {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if !in.Confirm {
		writeJSON(w, dbCleanResult{Now: s.dbFileBytes(), FloorMB: 64})
		return
	}
	if in.KeepMB < 64 {
		http.Error(w, "минимум 64 МБ", http.StatusBadRequest)
		return
	}
	res, err := s.cleanDown(int64(in.KeepMB) << 20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	res.KeepMB = in.KeepMB
	res.FloorMB = 64
	writeJSON(w, res)
}

func (s *Server) cleanDown(target int64) (dbCleanResult, error) {
	before := s.dbFileBytes()
	out := dbCleanResult{Now: before, FloorMB: 64}
	if target < 1 {
		target = 1
	}
	stopped := false
	for i := 0; i < 20000; i++ {
		used, err := sqliteDataBytes(s.st.DB)
		if err != nil {
			return dbCleanResult{}, err
		}
		if used <= target {
			break
		}
		var n int64
		err = s.st.Update(func(tx *sql.Tx) error {
			var e error
			n, e = trimStats(tx)
			return e
		})
		if err != nil {
			return dbCleanResult{}, err
		}
		if n == 0 {
			stopped = true
			break
		}
	}
	note, err := s.compactDB(before)
	if err != nil {
		return dbCleanResult{}, err
	}
	// VACUUM в режиме WAL пишет новую базу в журнал. Без слива журнала
	// размер «основной файл + журнал» после сжатия больше, чем до него.
	if err := s.st.ExecDirect(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return dbCleanResult{}, err
	}
	after := s.dbFileBytes()
	out.After = after
	out.Reached = after <= target+(1<<20)
	out.Detail = cleanDetail(before, after, target, out.Reached, stopped, note)
	return out, nil
}

func cleanDetail(before, after, target int64, reached, stopped bool, note string) string {
	if before <= target+(1<<20) && after <= target+(1<<20) {
		return "база уже " + mbText(after) + ", это не больше выбранных " + mbText(target)
	}
	msg := "база " + mbText(after)
	if !reached && stopped {
		msg = "получилось " + mbText(after) + ". ниже не опускается: оставшееся — настройки, правила, агенты и действующие ограничения"
	}
	if note != "" && !reached {
		msg += ". " + note
	}
	return msg
}

func mbText(n int64) string {
	if n < 1<<20 {
		return "меньше 1 МБ"
	}
	return fmt.Sprintf("%d МБ", (n+(1<<19))>>20)
}

func sqliteDataBytes(db *sql.DB) (int64, error) {
	var pages, free, size int64
	if err := db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := db.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil {
		return 0, err
	}
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&size); err != nil {
		return 0, err
	}
	if size < 1 {
		size = 4096
	}
	used := (pages - free) * size
	if used < 0 {
		used = 0
	}
	return used, nil
}

func (s *Server) compactDB(before int64) (string, error) {
	var mode int
	_ = s.st.DB.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode)
	_, free, err := diskSizeFn(s.dataDir())
	if err != nil {
		if mode == 2 {
			if _, vErr := s.st.DB.Exec(`PRAGMA incremental_vacuum`); vErr != nil {
				return "", vErr
			}
		}
		return "размер диска не прочитан, файл не переложен", nil
	}
	if free < uint64(before)+8<<20 {
		if mode == 2 {
			if _, vErr := s.st.DB.Exec(`PRAGMA incremental_vacuum`); vErr != nil {
				return "", vErr
			}
			return "на диске мало места, файл ужат только свободными страницами", nil
		}
		return "на диске мало места, файл не сжат", nil
	}
	if _, err := s.st.DB.Exec(`VACUUM`); err != nil {
		return "", err
	}
	return "", nil
}

func trimStats(tx *sql.Tx) (int64, error) {
	var n int64
	for _, q := range statTrimSQL {
		res, err := tx.Exec(q)
		if err != nil {
			return n, err
		}
		c, err := res.RowsAffected()
		if err != nil {
			return n, err
		}
		n += c
	}
	c, err := trimClosedAlerts(tx)
	n += c
	if err != nil {
		return n, err
	}
	c, err = trimDeadBlocks(tx)
	n += c
	return n, err
}

// Только то, что не нужно для работы. dns_seen кормит доменные правила,
// open_flows — текущие соединения: их обычная ротация тоже не трогает.
var statTrimSQL = []string{
	`DELETE FROM ssh_brute WHERE (remote_ip, host_id) IN (SELECT remote_ip, host_id FROM ssh_brute ORDER BY last_at_ms LIMIT 400)`,
	`DELETE FROM audit_log WHERE audit_id IN (SELECT audit_id FROM audit_log ORDER BY at_ms LIMIT 400)`,
	`DELETE FROM learn_questions WHERE question_id IN (SELECT question_id FROM learn_questions WHERE status!='open' ORDER BY last_seen_ms LIMIT 200)`,
	`DELETE FROM ingest_events WHERE event_id IN (SELECT e.event_id FROM ingest_events e WHERE e.seq < COALESCE((SELECT a.pending_from FROM agents a WHERE a.agent_id=e.agent_id), e.seq) ORDER BY e.received_at_ms LIMIT 400)`,
}

func trimClosedAlerts(tx *sql.Tx) (int64, error) {
	rows, err := tx.Query(`SELECT alert_id FROM alerts WHERE closed_at_ms IS NOT NULL ORDER BY opened_at_ms LIMIT 200`)
	if err != nil {
		return 0, err
	}
	ids, err := scanIDs(rows)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	ph, args := sqlArgs(ids)
	for _, q := range []string{
		`DELETE FROM alert_refs WHERE alert_id IN (` + ph + `)`,
		`DELETE FROM notifications WHERE alert_id IN (` + ph + `)`,
		`DELETE FROM alerts WHERE alert_id IN (` + ph + `)`,
	} {
		if _, err := tx.Exec(q, args...); err != nil {
			return 0, err
		}
	}
	return int64(len(ids)), nil
}

func trimDeadBlocks(tx *sql.Tx) (int64, error) {
	rows, err := tx.Query(`SELECT block_id FROM blocks WHERE state IN ('expired','removed') AND NOT EXISTS (SELECT 1 FROM commands c WHERE c.block_id=blocks.block_id AND c.acked_at_ms IS NULL) ORDER BY created_at_ms LIMIT 100`)
	if err != nil {
		return 0, err
	}
	ids, err := scanIDs(rows)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	ph, args := sqlArgs(ids)
	for _, q := range []string{
		`DELETE FROM commands WHERE block_id IN (` + ph + `)`,
		`DELETE FROM block_pause WHERE block_id IN (` + ph + `)`,
		`DELETE FROM blocks WHERE block_id IN (` + ph + `)`,
	} {
		if _, err := tx.Exec(q, args...); err != nil {
			return 0, err
		}
	}
	return int64(len(ids)), nil
}

func scanIDs(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func sqlArgs(ids []string) (string, []any) {
	parts := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		parts[i] = "?"
		args[i] = id
	}
	return strings.Join(parts, ","), args
}
