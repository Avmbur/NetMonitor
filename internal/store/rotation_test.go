package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestRotationAcrossTablesKeepsNewestHistory(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const limit = 1 << 20
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "db_max_bytes", strconv.Itoa(limit)) }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 200; i++ {
		err := st.Update(func(tx *sql.Tx) error {
			if i%2 == 0 {
				_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)", fmt.Sprint(i), i, strings.Repeat("a", 16384))
				return err
			}
			_, err := tx.Exec("INSERT INTO collector_health(event_id,host_id,observed_at_ms,received_at_ms,kind,note) VALUES(?,'h',?,?,'test',?)", fmt.Sprint(i), i, i, strings.Repeat("h", 16384))
			return err
		})
		if err != nil {
			t.Fatal(i, err)
		}
		if size := sqliteFileBytes(st.Path()) + sqliteFileBytes(st.Path()+"-wal"); size > limit {
			t.Fatal("size", size)
		}
	}
	var count, oldest, newest int
	if err := st.DB.QueryRow("SELECT count(*),min(t),max(t) FROM (SELECT at_ms t FROM audit_log UNION ALL SELECT observed_at_ms t FROM collector_health)").Scan(&count, &oldest, &newest); err != nil {
		t.Fatal(err)
	}
	if count >= 200 || oldest != 201-count || newest != 200 {
		t.Fatalf("global order broken: count=%d range=%d..%d", count, oldest, newest)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained newest %d records across two tables: %d..%d", count, oldest, newest)
}

func TestRotationDoesNotStartAtNinetyPercent(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO audit_log VALUES('keep',1,'adm','test','',?,'')", strings.Repeat("a", 300000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var pages, size int64
	if err := st.DB.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("PRAGMA page_size").Scan(&size); err != nil {
		t.Fatal(err)
	}
	limit := (pages + 2) * size
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "db_max_bytes", fmt.Sprint(limit)) }); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE audit_id='keep'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("early eviction: %d %v", n, err)
	}
	if pages*size*10 <= limit*9 {
		t.Fatal("fixture is below 90 percent")
	}
}

func TestRotationFailureRollsBackBothIncomingAndDeletedHistory(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", fmt.Sprint(1<<20)); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO audit_log VALUES('old',1,'adm','test','',?,'')", strings.Repeat("a", 300000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = st.Update(func(tx *sql.Tx) error {
		calls++
		_, err := tx.Exec("INSERT INTO audit_log VALUES('incoming',2,'adm','test','',?,'')", strings.Repeat("b", 1200000))
		return err
	})
	if !errors.Is(err, ErrDatabaseFull) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("callback replayed", calls)
	}
	var ids string
	if err := st.DB.QueryRow("SELECT group_concat(audit_id) FROM audit_log").Scan(&ids); err != nil || ids != "old" {
		t.Fatalf("partial transaction: %q %v", ids, err)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
}

func TestRotationProtectsUpdatedOldRecord(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", fmt.Sprint(1<<20)); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO audit_log VALUES('oldest',1,'adm','test','',?,''),('later',2,'adm','test','',?,'')", strings.Repeat("a", 250000), strings.Repeat("b", 250000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE audit_log SET detail=? WHERE audit_id='oldest'", strings.Repeat("c", 600000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var ids string
	if err := st.DB.QueryRow("SELECT group_concat(audit_id) FROM audit_log").Scan(&ids); err != nil || ids != "oldest" {
		t.Fatalf("new update lost: %q %v", ids, err)
	}
}

func TestRotationOrdersMinuteAndHourHistoryAndProtectsUpdate(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		for _, q := range []string{
			"INSERT INTO traffic_1m VALUES('h',100,'out','internet',1,2,3)",
			"INSERT INTO traffic_1m VALUES('h',300,'in','internet',1,2,3)",
			"INSERT INTO traffic_1h VALUES('h',200,'out','internet',1,2,3,0)",
			"INSERT INTO audit_log VALUES('later',400,'adm','test','','','')",
		} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE traffic_1m SET bytes_out=bytes_out+10 WHERE bucket_start_ms=100"); err != nil {
			return err
		}
		if err := deleteOldestHistory(context.Background(), tx, NowMS()); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM traffic_1h").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("hour history not selected before later minute: %d", n)
		}
		return deleteOldestHistory(context.Background(), tx, NowMS())
	}); err != nil {
		t.Fatal(err)
	}
	var stamp, out int
	if err := st.DB.QueryRow("SELECT bucket_start_ms,bytes_out FROM traffic_1m").Scan(&stamp, &out); err != nil || stamp != 100 || out != 11 {
		t.Fatalf("updated aggregate lost: %d/%d %v", stamp, out, err)
	}
	var n int
	if err := st.DB.QueryRow("SELECT count(*) FROM audit_log").Scan(&n); err != nil || n != 1 {
		t.Fatalf("newer audit lost: %d %v", n, err)
	}
}
