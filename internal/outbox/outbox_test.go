package outbox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/store"
	"strings"
	"testing"
)

func TestBoundedSpoolExactLossAndPriority(t *testing.T) {
	st, e := store.OpenAgent(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if e = st.Update(func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO meta(k,v) VALUES('queue_limit','16000')"); e != nil {
			return e
		}
		if e := Insert(tx, "question", 7, map[string]string{"question": "keep"}, 1); e != nil {
			return e
		}
		for i := 0; i < 100; i++ {
			if e := Insert(tx, "sample", 0, map[string]string{"data": strings.Repeat("x", 500)}, int64(i+2)); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var bytes, n int
	if e = st.DB.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_bytes'").Scan(&bytes); e != nil {
		t.Fatal(e)
	}
	if bytes > 16000 {
		t.Fatal(bytes)
	}
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 1 {
		t.Fatal("question dropped before samples")
	}
	// Every assigned sequence is either present or explicitly reported lost.
	live := map[int64]bool{}
	lost := map[int64]bool{}
	rows, e := st.DB.Query("SELECT seq,kind,payload FROM outbox")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var seq int64
		var kind, raw string
		rows.Scan(&seq, &kind, &raw)
		live[seq] = true
		if kind == "queue_drop" {
			var p Loss
			if e = json.Unmarshal([]byte(raw), &p); e != nil {
				t.Fatal(e)
			}
			for _, r := range p.Ranges {
				for n := r.First; n <= r.Last; n++ {
					lost[n] = true
				}
			}
		}
	}
	rows.Close()
	var seq int64
	st.DB.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='next_seq'").Scan(&seq)
	for i := int64(1); i <= seq; i++ {
		if !live[i] && !lost[i] {
			t.Fatal(fmt.Sprint("unreported sequence ", i))
		}
	}
	// Rollback includes both trimming and the loss event.
	before := seq
	e = st.Update(func(tx *sql.Tx) error {
		if e := Insert(tx, "sample", 0, map[string]string{"data": strings.Repeat("q", 15000)}, 1000); e != nil {
			return e
		}
		return fmt.Errorf("injected")
	})
	if e == nil {
		t.Fatal("missing injected error")
	}
	st.DB.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='next_seq'").Scan(&seq)
	if seq != before {
		t.Fatal("partial loss transaction")
	}
}

func TestLowDiskSpaceShrinksQueue(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Update(func(tx *sql.Tx) error {
		for i := 0; i < 20; i++ {
			if err := Insert(tx, "sample", 0, map[string]string{"data": strings.Repeat("x", 1000)}, int64(i+1)); err != nil {
				return err
			}
		}
		return Capacity(tx, 8192, 100)
	}); err != nil {
		t.Fatal(err)
	}
	var size, limit int64
	if err = st.DB.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_bytes'").Scan(&size); err != nil {
		t.Fatal(err)
	}
	if err = st.DB.QueryRow("SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_limit'").Scan(&limit); err != nil {
		t.Fatal(err)
	}
	if limit != 4096 || size > limit {
		t.Fatalf("limit=%d size=%d", limit, size)
	}
	var n int
	if err = st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='queue_drop'").Scan(&n); err != nil || n < 1 {
		t.Fatal("missing low-space loss report", n, err)
	}
}

func TestQuestionMergesRepeats(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	q := map[string]any{"dedup_key": "out|tcp|1.1.1.1|443||", "remote_ip": "1.1.1.1", "repeats": 1}
	if err = st.Update(func(tx *sql.Tx) error {
		if err := Insert(tx, "question", 7, q, 1); err != nil {
			return err
		}
		return Insert(tx, "question", 7, q, 2)
	}); err != nil {
		t.Fatal(err)
	}
	var n, repeats, events int
	st.DB.QueryRow("SELECT COUNT(*), MAX(repeats) FROM local_questions").Scan(&n, &repeats)
	st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='question'").Scan(&events)
	if n != 1 || repeats != 2 || events != 1 {
		t.Fatalf("n=%d repeats=%d events=%d", n, repeats, events)
	}
}

func TestQuestionDoesNotMergeIntoSentEvent(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	q := map[string]any{"dedup_key": "out|tcp|1.1.1.1|443||", "remote_ip": "1.1.1.1", "repeats": 1}
	if err = st.Update(func(tx *sql.Tx) error {
		if err := Insert(tx, "question", 7, q, 1); err != nil {
			return err
		}
		var id string
		if err := tx.QueryRow("SELECT question_id FROM local_questions").Scan(&id); err != nil {
			return err
		}
		if err := MarkQuestionsSent(tx, []string{id}); err != nil {
			return err
		}
		return Insert(tx, "question", 7, q, 2)
	}); err != nil {
		t.Fatal(err)
	}
	var n, events int
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='question'").Scan(&events)
	if n != 2 || events != 2 {
		t.Fatalf("in-flight merge lost a later attempt n=%d events=%d", n, events)
	}
}
