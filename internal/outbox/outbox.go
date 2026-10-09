package outbox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"sort"
	"strconv"
)

func Insert(tx *sql.Tx, kind string, priority int, payload any, now int64) error {
	if err := insert(tx, kind, priority, payload, now); err != nil {
		return err
	}
	return trim(tx, now)
}

// InsertUntrimmed is for callers that also own an in-memory queue.
// They must apply Trim to the combined queue in the same transaction.
func InsertUntrimmed(tx *sql.Tx, kind string, priority int, payload any, now int64) error {
	return insert(tx, kind, priority, payload, now)
}

func insert(tx *sql.Tx, kind string, priority int, payload any, now int64) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	lane := "history"
	if priority >= 5 {
		lane = "urgent"
	}
	if kind == "health" {
		var p struct{ Kind string }
		if err = json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if p.Kind == "alive" {
			lane = "heartbeat"
		}
	}
	if kind == "question" {
		merged, err := mergeQuestion(tx, raw)
		if err != nil || merged {
			return err
		}
	}
	seq, err := Next(tx)
	if err != nil {
		return err
	}
	id := idgen.NewV7()
	if _, err = tx.Exec("INSERT INTO outbox(event_id,seq,kind,priority,lane,payload,created_at_ms) VALUES(?,?,?,?,?,?,?)", id, seq, kind, priority, lane, string(raw), now); err != nil {
		return err
	}
	if kind == "question" {
		_, err = tx.Exec("INSERT INTO local_questions(question_id,created_at_ms,payload,repeats,sent) VALUES(?,?,?,1,0)", id, now, string(raw))
	}
	return err
}

func mergeQuestion(tx *sql.Tx, raw []byte) (bool, error) {
	var in protocol.QuestionPayload
	if err := json.Unmarshal(raw, &in); err != nil {
		return false, err
	}
	if in.DedupKey == "" {
		return false, nil
	}
	rows, err := tx.Query("SELECT question_id, payload, repeats FROM local_questions WHERE sent=0")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, payload string
		var n int
		if err = rows.Scan(&id, &payload, &n); err != nil {
			return false, err
		}
		var old protocol.QuestionPayload
		if json.Unmarshal([]byte(payload), &old) != nil || old.DedupKey != in.DedupKey {
			continue
		}
		n++
		old.Repeats = n
		if in.ProcPath != "" {
			old.ProcPath = in.ProcPath
		}
		if in.ProcComm != "" {
			old.ProcComm = in.ProcComm
		}
		if in.Container != "" {
			old.Container = in.Container
		}
		body, err := json.Marshal(old)
		if err != nil {
			return false, err
		}
		if _, err = tx.Exec("UPDATE local_questions SET payload=?,repeats=? WHERE question_id=?", string(body), n, id); err != nil {
			return false, err
		}
		if _, err = tx.Exec("UPDATE outbox SET payload=? WHERE event_id=?", string(body), id); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, rows.Err()
}

func MarkQuestionsSent(tx *sql.Tx, ids []string) error {
	for _, id := range ids {
		if id == "" {
			continue
		}
		// Повторная отправка уже отмеченного вопроса страницу базы не переписывает.
		if _, err := tx.Exec("UPDATE local_questions SET sent=1 WHERE question_id=? AND COALESCE(sent,0)!=1", id); err != nil {
			return err
		}
	}
	return nil
}

func Next(tx *sql.Tx) (int64, error) {
	var s string
	err := tx.QueryRow("SELECT v FROM meta WHERE k='next_seq'").Scan(&s)
	n := int64(0)
	if err == nil {
		n, err = strconv.ParseInt(s, 10, 64)
	} else if err == sql.ErrNoRows {
		err = nil
	}
	if err != nil {
		return 0, fmt.Errorf("sequence: %w", err)
	}
	n++
	_, err = tx.Exec("INSERT INTO meta(k,v) VALUES('next_seq',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", strconv.FormatInt(n, 10))
	return n, err
}

type Range struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
}
type Loss struct {
	Kind       string  `json:"kind"`
	Ranges     []Range `json:"ranges"`
	LostEvents int64   `json:"lost_events"`
	QueueBytes int64   `json:"queue_bytes"`
	Note       string  `json:"note"`
}

const MaxBytes int64 = 32 << 20

// Trim применяет уже записанный предел очереди и не меняет queue_limit.
func Trim(tx *sql.Tx, now int64) error {
	return trim(tx, now)
}

func trim(tx *sql.Tx, now int64) error {
	var total int64
	if err := tx.QueryRow("SELECT COALESCE((SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_bytes'),0)").Scan(&total); err != nil {
		return err
	}
	limit := MaxBytes
	if err := tx.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_limit'").Scan(&limit); err != nil && err != sql.ErrNoRows {
		return err
	}
	limit = max(limit, 4096)
	if total <= limit {
		return nil
	}
	target := limit / 2
	rows, err := tx.Query("SELECT event_id,seq,kind,payload,length(CAST(payload AS BLOB))+256 FROM outbox ORDER BY CASE WHEN kind='sample' THEN 0 WHEN kind='health' THEN 1 WHEN kind='queue_drop' THEN 3 ELSE 2 END,seq")
	if err != nil {
		return err
	}
	type drop struct {
		id        string
		seq       int64
		kind, raw string
		size      int64
	}
	var drops []drop
	for rows.Next() && total > target {
		var d drop
		if err = rows.Scan(&d.id, &d.seq, &d.kind, &d.raw, &d.size); err != nil {
			rows.Close()
			return err
		}
		drops = append(drops, d)
		total -= d.size
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var spans []Range
	for _, d := range drops {
		spans = append(spans, Range{d.seq, d.seq})
		if d.kind == "queue_drop" {
			var loss Loss
			if err = json.Unmarshal([]byte(d.raw), &loss); err != nil {
				return err
			}
			spans = append(spans, loss.Ranges...)
		}
		if _, err = tx.Exec("DELETE FROM local_questions WHERE question_id=?", d.id); err != nil {
			return err
		}
		if _, err = tx.Exec("DELETE FROM outbox WHERE event_id=?", d.id); err != nil {
			return err
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].First < spans[j].First })
	merged := []Range{}
	for _, r := range spans {
		n := len(merged)
		if n > 0 && r.First <= merged[n-1].Last+1 {
			merged[n-1].Last = max(r.Last, merged[n-1].Last)
		} else {
			merged = append(merged, r)
		}
	}
	var count int64
	for _, r := range merged {
		count += r.Last - r.First + 1
	}
	return insert(tx, "queue_drop", 10, Loss{"queue_drop", merged, count, total, "outbox limit; ranges are exact, priority reordering is not loss"}, now)
}

// Reserve space for SQLite pages, WAL and a loss report. The limit can only fall
// below the fixed spool cap; low space never expands the queue.
func Capacity(tx *sql.Tx, free uint64, now int64) error {
	if err := SetCapacity(tx, free); err != nil {
		return err
	}
	return trim(tx, now)
}

// SetCapacity changes the limit; callers with a RAM queue trim both sources.
func SetCapacity(tx *sql.Tx, free uint64) error {
	limit := MaxBytes
	if free < 128<<20 {
		limit = max(4096, int64(free/4))
	}
	// Пульс зовёт это каждые 10 секунд: то же значение страницу не переписывает.
	if _, err := tx.Exec("INSERT INTO meta(k,v) VALUES('queue_limit',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v WHERE meta.v IS NOT excluded.v", strconv.FormatInt(limit, 10)); err != nil {
		return err
	}
	return nil
}
