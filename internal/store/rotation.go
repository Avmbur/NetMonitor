package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrDatabaseFull = errors.New("database full: no removable history fits the size limit")

type historyTable struct {
	name, stamp, eligible string
	keys                  []string
}

// Only completed history is disposable. Live policy, queue receipts and
// records needed by active detection are never candidates.
var historyTables = []historyTable{
	{"flow_samples", "t0_ms", "1", []string{"rowid"}},
	{"firewall_events", "observed_at_ms", "1", []string{"rowid"}},
	{"traffic_1m", "bucket_start_ms", "1", []string{"host_id", "bucket_start_ms", "direction", "remote_scope"}},
	{"flows", "last_seen_at_ms", "ended_at_ms IS NOT NULL AND NOT EXISTS (SELECT 1 FROM flow_samples WHERE flow_samples.flow_uid=h.flow_uid)", []string{"rowid"}},
	{"collector_health", "observed_at_ms", "kind!='alive'", []string{"rowid"}},
	{"audit_log", "at_ms", "1", []string{"rowid"}},
	{"learn_questions", "last_seen_ms", "status!='open'", []string{"rowid"}},
	{"traffic_1h", "bucket_start_ms", "1", []string{"host_id", "bucket_start_ms", "direction", "remote_scope"}},
	{"ssh_failures", "observed_at_ms", "observed_at_ms<:ssh_cut", []string{"rowid"}},
}

func historyKey(h historyTable, prefix string) string {
	keys := make([]string, len(h.keys))
	for i, k := range h.keys {
		keys[i] = prefix + k
	}
	return "json_array(" + strings.Join(keys, ",") + ")"
}

func (s *owner) prepareRotation() error {
	ctx := context.Background()
	var mode int
	if err := s.conn.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return err
	}
	if mode != 2 {
		if _, err := s.conn.ExecContext(ctx, "PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return err
		}
		// Enabling page relocation on an existing database requires one rebuild.
		if mode == 0 {
			if _, err := s.conn.ExecContext(ctx, "VACUUM"); err != nil {
				return err
			}
		}
	}
	if _, err := s.conn.ExecContext(ctx, "PRAGMA temp_store=MEMORY"); err != nil {
		return err
	}
	if _, err := s.conn.ExecContext(ctx, "CREATE TEMP TABLE rotation_touched(source INTEGER,key TEXT,PRIMARY KEY(source,key)) WITHOUT ROWID"); err != nil {
		return err
	}
	// These connection-local triggers protect the current write, including an
	// update of an old aggregate. They create no additional persistent database.
	for i, h := range historyTables {
		for _, event := range []string{"INSERT", "UPDATE"} {
			q := fmt.Sprintf("CREATE TEMP TRIGGER rotation_%d_%s AFTER %s ON main.%s BEGIN INSERT OR IGNORE INTO rotation_touched VALUES(%d,%s); END", i, event, event, h.name, i, historyKey(h, "new."))
			if _, err := s.conn.ExecContext(ctx, q); err != nil {
				return err
			}
		}
	}
	return nil
}

// Each table contributes its oldest eligible row; the outer ordering chooses
// the oldest of those rows, without quotas or priority between tables.
func oldestHistorySQL() string {
	parts := make([]string, len(historyTables))
	for i, h := range historyTables {
		key := historyKey(h, "h.")
		parts[i] = fmt.Sprintf("SELECT * FROM (SELECT %d AS source,%s AS key,h.%s AS stamp FROM %s h WHERE (%s) AND NOT EXISTS (SELECT 1 FROM temp.rotation_touched t WHERE t.source=%d AND t.key=%s) ORDER BY h.%s LIMIT 1)", i, key, h.stamp, h.name, h.eligible, i, key, h.stamp)
	}
	return "SELECT source,key FROM (" + strings.Join(parts, " UNION ALL ") + ") ORDER BY stamp,source LIMIT 1"
}

var oldestHistory = oldestHistorySQL()

func deleteOldestHistory(ctx context.Context, tx *sql.Tx, now int64) error {
	var source int
	var key string
	err := tx.QueryRowContext(ctx, oldestHistory, sql.Named("ssh_cut", now-86400000)).Scan(&source, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDatabaseFull
	}
	if err != nil {
		return err
	}
	h := historyTables[source]
	var args []any
	decoder := json.NewDecoder(strings.NewReader(key))
	decoder.UseNumber()
	if err := decoder.Decode(&args); err != nil {
		return err
	}
	where := make([]string, len(h.keys))
	for i, k := range h.keys {
		where[i] = k + "=?"
		if n, ok := args[i].(json.Number); ok {
			v, err := n.Int64()
			if err != nil {
				return err
			}
			args[i] = v
		}
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM "+h.name+" WHERE "+strings.Join(where, " AND "), args...)
	return err
}

// Called once, after the caller has written but before COMMIT. Deletions and
// the incoming data either commit together or roll back together.
func rotateHistory(ctx context.Context, tx *sql.Tx) error {
	max, err := MonitorCapBytes(tx)
	if err != nil {
		return err
	}
	var pageSize, pages, free int64
	if err := tx.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	limit := max / pageSize
	now := NowMS()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
			return err
		}
		if pages <= limit {
			return nil
		}
		if err := tx.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil {
			return err
		}
		if free > 0 {
			// Consume every result row: incremental_vacuum can yield after each page.
			rows, err := tx.Query(fmt.Sprintf("PRAGMA incremental_vacuum(%d)", pages-limit))
			if err != nil {
				return err
			}
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			continue
		}
		if err := deleteOldestHistory(ctx, tx, now); err != nil {
			return err
		}
	}
}
