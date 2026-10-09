package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
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
			_, err := tx.Exec("INSERT INTO ssh_brute(remote_ip,host_id,attempts,first_at_ms,last_at_ms) VALUES(?,?,1,?,?)", fmt.Sprint(i), strings.Repeat("h", 16384), i, i)
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
	if err := st.DB.QueryRow("SELECT count(*),min(t),max(t) FROM (SELECT at_ms t FROM audit_log UNION ALL SELECT last_at_ms t FROM ssh_brute)").Scan(&count, &oldest, &newest); err != nil {
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
	// Лимит файла — заданный размер без запаса под журнал (walReserve = 1/16).
	limit := ((pages+2)*size*16 + 14) / 15
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
	// Пустая схема вместе со снимком открытых и защищённая строка на 600 КиБ
	// должны умещаться под 95% лимита. Незащищённая строка при этом ещё срезается.
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", fmt.Sprint(1280<<10)); err != nil {
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

func TestRotationReusesFreePages(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const limit = 1 << 20
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "db_max_bytes", strconv.Itoa(limit)) }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 80; i++ {
		n := i
		if err := st.Update(func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)", fmt.Sprint(n), n, strings.Repeat("a", 16384))
			return err
		}); err != nil {
			t.Fatal(n, err)
		}
	}
	var marked int
	if err := st.DB.QueryRow("SELECT count(*) FROM audit_log").Scan(&marked); err != nil {
		t.Fatal(err)
	}
	trimmed := false
	for n := 81; n <= 120 && !trimmed; n++ {
		if err := st.Update(func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)", fmt.Sprint(n), n, strings.Repeat("b", 16384))
			return err
		}); err != nil {
			t.Fatal(n, err)
		}
		var now int
		if err := st.DB.QueryRow("SELECT count(*) FROM audit_log").Scan(&now); err != nil {
			t.Fatal(err)
		}
		if now <= marked {
			trimmed = true
		}
		marked = now
	}
	if !trimmed {
		t.Fatal("history never trimmed")
	}
	var pages, free, size, count, oldest int64
	if err := st.DB.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("PRAGMA freelist_count").Scan(&free); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("PRAGMA page_size").Scan(&size); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("SELECT count(*),min(at_ms) FROM audit_log").Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if free < 1 {
		t.Fatal("trim left no free pages")
	}
	if pages*size > limit {
		t.Fatalf("file above cap: %d pages", pages)
	}
	limitPages := limit / size
	if (pages-free)*100 > limitPages*capHeadroomPercent {
		t.Fatalf("used %d of %d pages, want <= %d%%", pages-free, limitPages, capHeadroomPercent)
	}
	if err := st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES('extra',1000,'adm','test','fit')")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var pages2, free2, count2, oldest2 int64
	if err := st.DB.QueryRow("PRAGMA page_count").Scan(&pages2); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("PRAGMA freelist_count").Scan(&free2); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("SELECT count(*),min(at_ms) FROM audit_log").Scan(&count2, &oldest2); err != nil {
		t.Fatal(err)
	}
	if pages2 != pages {
		t.Fatalf("tail moved: pages %d -> %d", pages, pages2)
	}
	if count2 != count+1 || oldest2 != oldest {
		t.Fatalf("reuse rewrote history: count %d->%d oldest %d->%d", count, count2, oldest, oldest2)
	}
	if free2 > free {
		t.Fatalf("free pages grew: %d -> %d", free, free2)
	}
}

func TestLoweringCapShrinksFileAndKeepsActiveBan(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if err := PutSetting(tx, "db_max_bytes", strconv.Itoa(8<<20)); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO hosts(host_id,hostname) VALUES('h','box')"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO blocks(block_id,remote_ip,remote_ip_bin,reason,created_at_ms,expires_at_ms,state,scope_kind,source,created_by) VALUES('live','1.1.1.1',zeroblob(16),'manual',1,9999999999999,'active','all','manual','adm'),('dead','2.2.2.2',zeroblob(16),'manual',1,2,'expired','all','manual','adm')`); err != nil {
			return err
		}
		for i := 1; i <= 100; i++ {
			if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)", fmt.Sprint(i), i+10, strings.Repeat("b", 16384)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "db_max_bytes", strconv.Itoa(limit)) }); err != nil {
		t.Fatal(err)
	}
	var pages, size, audits int64
	if err := st.DB.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow("PRAGMA page_size").Scan(&size); err != nil {
		t.Fatal(err)
	}
	if pages*size > limit {
		t.Fatalf("lowered cap left %d bytes", pages*size)
	}
	var live, dead int
	if err := st.DB.QueryRow("SELECT count(*) FROM blocks WHERE block_id='live' AND state='active'").Scan(&live); err != nil || live != 1 {
		t.Fatalf("live flow: %d %v", live, err)
	}
	if err := st.DB.QueryRow("SELECT count(*) FROM blocks WHERE block_id='dead'").Scan(&dead); err != nil || dead != 0 {
		t.Fatalf("closed flow kept: %d %v", dead, err)
	}
	if err := st.DB.QueryRow("SELECT count(*) FROM audit_log").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits >= 100 {
		t.Fatalf("history not trimmed: %d", audits)
	}
	var newest int
	if err := st.DB.QueryRow("SELECT max(at_ms) FROM audit_log").Scan(&newest); err != nil || newest != 110 {
		t.Fatalf("newest audit: %d %v", newest, err)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
}

// У потолка файл стоит на лимите без запаса под журнал: обычная запись не
// сливает журнал, а первая срезка идёт пачками и не держит писателя минутами.
func TestCapKeepsWALAndTrimsInBatches(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const limit = 4 << 20
	if err := st.Update(func(tx *sql.Tx) error { return PutSetting(tx, "db_max_bytes", strconv.Itoa(limit)) }); err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 150)
	n := 0
	write := func(rows int) time.Duration {
		t0 := time.Now()
		if err := st.Update(func(tx *sql.Tx) error {
			for i := 0; i < rows; i++ {
				n++
				if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)", fmt.Sprint(n), n, pad); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(n, err)
		}
		return time.Since(t0)
	}
	var slowest time.Duration
	for i := 0; i < 200; i++ {
		if d := write(200); d > slowest {
			slowest = d
		}
	}
	if slowest > 2*time.Second {
		t.Fatalf("trim held the writer %v", slowest)
	}
	var pages int64
	if err := st.DB.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages*4096 > limit-walReserve(limit) {
		t.Fatalf("file %d pages above cap without WAL reserve", pages)
	}
	// После слива журнал держит только последнюю запись — несколько страниц.
	resets := 0
	for i := 0; i < 40; i++ {
		write(1)
		if sqliteFileBytes(st.Path()+"-wal") < 32<<10 {
			resets++
		}
	}
	if resets > 10 {
		t.Fatalf("WAL reset on %d of 40 writes at cap", resets)
	}
	if size := sqliteFileBytes(st.Path()) + sqliteFileBytes(st.Path()+"-wal"); size > limit {
		t.Fatalf("file and WAL %d above cap", size)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
}

func TestRotationSmallOverflowKeepsLargeHistoryRows(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		for i := 1; i <= 16; i++ {
			if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,detail) VALUES(?,?,'adm','test',?)",
				fmt.Sprint(i), i, strings.Repeat("x", 64<<10)); err != nil {
				return err
			}
		}
		return nil
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
	// The current file fits the total budget; only WAL reserve and headroom
	// require trimming. A small overflow must not erase all sixteen records.
	limit := pages * size
	if err := st.Update(func(tx *sql.Tx) error {
		return PutSetting(tx, "db_max_bytes", fmt.Sprint(limit))
	}); err != nil {
		t.Fatal(err)
	}
	var count, newest int
	if err := st.DB.QueryRow("SELECT count(*),COALESCE(max(at_ms),0) FROM audit_log").Scan(&count, &newest); err != nil {
		t.Fatal(err)
	}
	if count < 12 || count >= 16 || newest != 16 {
		t.Fatalf("small overflow removed too much history: count=%d newest=%d", count, newest)
	}
	if err := Integrity(st.Path()); err != nil {
		t.Fatal(err)
	}
}

func TestRotationOldBanWithCommands(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO blocks(block_id,scope_kind,state,reason,source,created_by,created_at_ms) VALUES('old','all','expired','manual','manual','adm',1),('active','all','active','manual','manual','adm',0)`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,block_id,created_at_ms,acked_at_ms) VALUES('done','a','ban','{}','old',1,2)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(tx *sql.Tx) error { return deleteOldestHistory(context.Background(), tx, NowMS(), 10) }); err != nil {
		t.Fatal(err)
	}
	var ids string
	if err := st.DB.QueryRow("SELECT group_concat(block_id) FROM blocks").Scan(&ids); err != nil || ids != "active" {
		t.Fatal(ids, err)
	}
	var n int
	if err := st.DB.QueryRow("SELECT COUNT(*) FROM commands").Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
