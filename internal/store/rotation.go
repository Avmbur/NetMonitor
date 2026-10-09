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
	{"audit_log", "at_ms", "1", []string{"rowid"}},
	{"learn_questions", "last_seen_ms", "status!='open'", []string{"rowid"}},
	{"ssh_brute", "last_at_ms", "1", []string{"remote_ip", "host_id"}},
	{"blocks", "created_at_ms", "state IN ('expired','removed') AND NOT EXISTS (SELECT 1 FROM commands c WHERE c.block_id=h.block_id AND c.acked_at_ms IS NULL)", []string{"block_id"}},
}

func historyKey(h historyTable, prefix string) string {
	keys := make([]string, len(h.keys))
	for i, k := range h.keys {
		keys[i] = prefix + k
	}
	return "json_array(" + strings.Join(keys, ",") + ")"
}

func prefixed(keys []string, prefix string) string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = prefix + k
	}
	return strings.Join(out, ",")
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
		key := historyKey(h, "new.")
		for _, event := range []string{"INSERT", "UPDATE"} {
			// Повтор той же строки в одной транзакции роняет INSERT OR IGNORE (1555).
			q := fmt.Sprintf("CREATE TEMP TRIGGER rotation_%d_%s AFTER %s ON main.%s BEGIN INSERT INTO rotation_touched(source,key) SELECT %d,%s WHERE NOT EXISTS (SELECT 1 FROM rotation_touched WHERE source=%d AND key=%s); END", i, event, event, h.name, i, key, i, key)
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
	return "SELECT source,key,stamp FROM (" + strings.Join(parts, " UNION ALL ") + ") ORDER BY stamp,source LIMIT 2"
}

var oldestHistory = oldestHistorySQL()

// Срезка пачкой: строки самой старой таблицы, которые старше любой строки
// других таблиц. Порядок «старое первым» тот же, что при удалении по одной,
// но поиск по всем таблицам идёт раз на пачку, а не на строку.
// Пачка растёт с одной строки до 500: небольшое превышение лимита не должно
// сразу удалять шестнадцать крупных записей. Между пачками проверяем свободное место.
const (
	rotationBatchFirst = 1
	rotationBatch      = 500
)

func deleteOldestHistory(ctx context.Context, tx *sql.Tx, now int64, batch int) error {
	rows, err := tx.QueryContext(ctx, oldestHistory)
	if err != nil {
		return err
	}
	var source int
	var key string
	var stamp, nextStamp sql.NullInt64
	found, second := false, false
	for rows.Next() {
		var s int
		var k string
		var st sql.NullInt64
		if err := rows.Scan(&s, &k, &st); err != nil {
			rows.Close()
			return err
		}
		if !found {
			source, key, stamp, found = s, k, st, true
		} else {
			nextStamp, second = st, true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if !found {
		return ErrDatabaseFull
	}
	h := historyTables[source]
	if h.name != "blocks" && batch > 1 && stamp.Valid && (!second || nextStamp.Valid && nextStamp.Int64 > stamp.Int64) {
		cols := strings.Join(h.keys, ",")
		bound := ""
		var args []any
		if second {
			// Равные метки разных таблиц не трогаем пачкой: их рассудит удаление по одной.
			bound = " AND h." + h.stamp + "<:next_stamp"
			args = append(args, sql.Named("next_stamp", nextStamp.Int64))
		}
		q := fmt.Sprintf("DELETE FROM %s WHERE (%s) IN (SELECT %s FROM %s h WHERE (%s)%s AND NOT EXISTS (SELECT 1 FROM temp.rotation_touched t WHERE t.source=%d AND t.key=%s) ORDER BY h.%s LIMIT %d)",
			h.name, cols, prefixed(h.keys, "h."), h.name, h.eligible, bound, source, historyKey(h, "h."), h.stamp, batch)
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n > 0 {
			return err
		}
	}
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
	if h.name == "blocks" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM commands WHERE block_id=? AND acked_at_ms IS NOT NULL", args[0]); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM block_pause WHERE block_id=?", args[0]); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM "+h.name+" WHERE "+strings.Join(where, " AND "), args...)
	return err
}

// Доля лимита, которую оставляем занятой после срезки. Остальное — свободные
// страницы внутри файла: следующие записи занимают их и хвост не переносят.
const capHeadroomPercent = 95

// Перед COMMIT. Лимит файла — заданный размер без запаса под журнал (walReserve).
// Пока страниц не больше лимита, файл не трогает.
// Выше лимита срезает законченную историю, пока занято не больше 95%,
// и одним incremental_vacuum возвращает хвост к лимиту. Уменьшение лимита
// в настройках идёт тем же путём. Удаление и новая запись коммитятся вместе.
func rotateHistory(ctx context.Context, tx *sql.Tx) error {
	max, err := MonitorCapBytes(tx)
	if err != nil {
		return err
	}
	var pageSize int64
	if err := tx.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	if pageSize < 1 {
		pageSize = 4096
	}
	limit := (max - walReserve(max)) / pageSize
	if limit < 1 {
		limit = 1
	}
	target := limit * capHeadroomPercent / 100
	if target < 1 {
		target = 1
	}
	now := NowMS()
	batch := rotationBatchFirst
	var previousUsed, previousDeleted int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var pages, free int64
		if err := tx.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
			return err
		}
		if pages <= limit {
			return nil
		}
		if err := tx.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil {
			return err
		}
		used := pages - free
		if used < 0 {
			used = 0
		}
		if used <= target {
			after, err := incrementalVacuum(tx, pages-limit)
			if err != nil {
				return err
			}
			if after >= pages {
				return ErrDatabaseFull
			}
			continue
		}
		// Once a batch has freed pages, use its actual yield to avoid doubling
		// past the remaining target and deleting the whole tail of history.
		if freed := previousUsed - used; freed > 0 && previousDeleted > 0 {
			needed := ((used-target)*previousDeleted + freed - 1) / freed
			if needed < 1 {
				needed = 1
			}
			batch = min(batch, int(needed))
		}
		err := deleteOldestHistory(ctx, tx, now, batch)
		if err == nil {
			previousUsed = used
			if err := tx.QueryRow("SELECT changes()").Scan(&previousDeleted); err != nil {
				return err
			}
		}
		if batch < rotationBatch {
			batch = min(batch*2, rotationBatch)
		}
		if err != nil {
			if errors.Is(err, ErrDatabaseFull) && free > 0 && used <= limit {
				after, verr := incrementalVacuum(tx, pages-limit)
				if verr != nil {
					return verr
				}
				if after <= limit {
					return nil
				}
			}
			return err
		}
	}
}

func incrementalVacuum(tx *sql.Tx, pages int64) (int64, error) {
	if pages < 1 {
		var left int64
		err := tx.QueryRow("PRAGMA page_count").Scan(&left)
		return left, err
	}
	// incremental_vacuum отдаёт строку на каждую страницу.
	rows, err := tx.Query(fmt.Sprintf("PRAGMA incremental_vacuum(%d)", pages))
	if err != nil {
		return 0, err
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var left int64
	if err := tx.QueryRow("PRAGMA page_count").Scan(&left); err != nil {
		return 0, err
	}
	return left, nil
}
