package server

import (
	"database/sql"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netmonitor/internal/store"
)

func TestSnapshotBackupNotRawCopy(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		return store.PutSetting(tx, "probe", "live")
	}); err != nil {
		t.Fatal(err)
	}
	dest, err := s.takeSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Integrity(dest); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		return store.PutSetting(tx, "probe", "after")
	}); err != nil {
		t.Fatal(err)
	}
	db, err := store.QueryOpen(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM settings WHERE k='probe'`).Scan(&v); err != nil || v != "live" {
		t.Fatal(v, err)
	}
	st := s.uiState("", "settings")
	if st.Settings["snap_at"] == "" {
		t.Fatal("snap_at missing")
	}
	w := httptest.NewRecorder()
	s.handleSnapshot(w, httptest.NewRequest("POST", "/ui/api/snapshot", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestDailySnapshotRotatesOldFiles(t *testing.T) {
	s, _ := batchFixture(t)
	dir := s.snapDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "netmon-19990101.sqlite")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "netmon-20200101.sqlite")
	if err := os.WriteFile(extra, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.dailySnapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old snapshot kept")
	}
	if _, err := os.Stat(extra); !os.IsNotExist(err) {
		t.Fatal("extra snapshot kept")
	}
	day := time.Now().UTC().Format("20060102")
	if _, err := os.Stat(filepath.Join(dir, "netmon-"+day+".sqlite")); err != nil {
		t.Fatal(err)
	}
}

func TestRetainKeepsMarkersAndReferencedFlows(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	old := now - 40*86400000
	gone := now - 100*86400000
	newer := now - 5*86400000
	s.st.DB.Exec(`INSERT INTO ingest_events(event_id,agent_id,seq,kind,payload_sha256,observed_at_ms,received_at_ms) VALUES('e1','a',1,'flow','x',?,?)`, gone, gone)
	s.st.DB.Exec(`INSERT INTO ingest_events(event_id,agent_id,seq,kind,payload_sha256,observed_at_ms,received_at_ms) VALUES('e2','a',2,'flow','y',?,?)`, now, now)
	s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ended_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
		VALUES('oldf','h','a','b',?,?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, gone, gone, gone, gone)
	s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ended_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
		VALUES('keepf','h','a','b',?,?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, newer, newer, newer, newer)
	s.st.DB.Exec(`INSERT INTO flow_samples(event_id,flow_uid,agent_id,t0_ms,t1_ms,orig_bytes_delta,reply_bytes_delta,orig_packets_delta,reply_packets_delta,bytes_out,bytes_in,pkts_out,pkts_in,quality,observed_at_ms,received_at_ms)
		VALUES('s-old','keepf','a',?,?,1,0,1,0,1,0,1,0,'ok',?,?)`, old, old+1000, old, old)
	s.st.DB.Exec(`INSERT INTO flow_samples(event_id,flow_uid,agent_id,t0_ms,t1_ms,orig_bytes_delta,reply_bytes_delta,orig_packets_delta,reply_packets_delta,bytes_out,bytes_in,pkts_out,pkts_in,quality,observed_at_ms,received_at_ms)
		VALUES('s-new','keepf','a',?,?,1,0,1,0,1,0,1,0,'ok',?,?)`, newer, newer+1000, newer, newer)
	if err := s.st.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "samples_n", "30") }); err != nil {
		t.Fatal(err)
	}
	if err := s.retainNow(now); err != nil {
		t.Fatal(err)
	}
	var samples, flows, markers int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM flow_samples`).Scan(&samples)
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&flows)
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM ingest_events`).Scan(&markers)
	if samples != 1 {
		t.Fatal("samples", samples)
	}
	if flows != 1 {
		t.Fatal("flows", flows)
	}
	if markers != 2 {
		t.Fatal("permanent event receipts", markers)
	}
}

func TestDiskNinetySkipsSamplesAndAlerts(t *testing.T) {
	s, _ := batchFixture(t)
	prev := diskSizeFn
	diskSizeFn = func(string) (uint64, uint64, error) { return 100, 5, nil }
	defer func() { diskSizeFn = prev }()
	if err := s.refreshDisk(); err != nil {
		t.Fatal(err)
	}
	var skip string
	s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='disk_skip_samples'`).Scan(&skip)
	if skip != "1" {
		t.Fatal(skip)
	}
	st := s.uiState("", "settings")
	if st.Monitor["disk_pct"] != 95 {
		t.Fatal(st.Monitor)
	}
	if len(st.Alerts) == 0 {
		t.Fatal("no disk alert")
	}
}

func TestImpossibleDbCapPreservesHistoryAndSetting(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ended_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
		VALUES('capf','h','a','b',?,?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := s.st.DB.Exec(`INSERT INTO flow_samples(event_id,flow_uid,agent_id,t0_ms,t1_ms,orig_bytes_delta,reply_bytes_delta,orig_packets_delta,reply_packets_delta,bytes_out,bytes_in,pkts_out,pkts_in,quality,observed_at_ms,received_at_ms)
			VALUES(?,?,?,?,?,1,0,1,0,1,0,1,0,'ok',?,?)`, "cap-"+strconv.Itoa(i), "capf", "a", now-int64(i)*1000, now, now, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.st.Update(func(tx *sql.Tx) error { return store.PutSetting(tx, "db_max_bytes", "8192") }); !errors.Is(err, errDbCap) {
		t.Fatal(err)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM flow_samples`).Scan(&n)
	if n != 40 {
		t.Fatal("failed resize destroyed history", n)
	}
	if got := dbCapBytes(s.st.DB); got != 2<<30 {
		t.Fatal("failed resize persisted", got)
	}
}
