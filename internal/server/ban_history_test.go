package server

import (
	"database/sql"
	"strings"
	"testing"

	"netmonitor/internal/store"
)

func TestBanCardHistoryAndExpiry(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "217.60.76.226", "h", true, "скан портов", "scan", now)
	}); err != nil {
		t.Fatal(err)
	}
	var blockID, detail string
	if err := s.st.DB.QueryRow(`SELECT block_id FROM blocks WHERE remote_ip='217.60.76.226'`).Scan(&blockID); err != nil {
		t.Fatal(err)
	}
	if err := s.st.DB.QueryRow(`SELECT detail FROM audit_log WHERE action='скан портов'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "все серверы") || !strings.Contains(detail, "до ") {
		t.Fatal(detail)
	}
	var ref string
	if err := s.st.DB.QueryRow(`SELECT ref_id FROM alert_refs WHERE ref_kind='block'`).Scan(&ref); err != nil || ref != blockID {
		t.Fatal(ref, err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,severity,summary)
		VALUES('old','scan',1,'h',?,?,'high','старый скан')`, "scan/"+blockID, now-10); err != nil {
		t.Fatal(err)
	}
	st := s.uiStateQ(stateQuery{Section: "policy"})
	if st.err != nil {
		t.Fatal(st.err)
	}
	var fresh, old uiAlert
	for _, a := range st.Alerts {
		if a.ID == "old" {
			old = a
		} else if a.Rule == "scan" {
			fresh = a
		}
	}
	if fresh.BanID != blockID || fresh.BanState != "active" || fresh.BanScope != "все серверы" || fresh.BanUntil == "" {
		t.Fatalf("fresh %+v", fresh)
	}
	if old.BanID != blockID || old.BanState != "active" {
		t.Fatalf("old %+v", old)
	}
	if len(st.Bans) != 1 || st.Bans[0].ID != blockID {
		t.Fatalf("live %+v", st.Bans)
	}
	if _, err := s.st.DB.Exec(`UPDATE blocks SET expires_at_ms=? WHERE block_id=?`, now-1, blockID); err != nil {
		t.Fatal(err)
	}
	// A pinned ban can be loaded after its deadline but before the expiry sweep.
	st = s.uiStateQ(stateQuery{Section: "policy", BanID: blockID})
	if st.err != nil {
		t.Fatal(st.err)
	}
	if len(st.Bans) != 1 || st.Bans[0].State != "expired" {
		t.Fatalf("overdue pinned ban must not be actionable: %+v", st.Bans)
	}
	if err := s.expireBlocks(now); err != nil {
		t.Fatal(err)
	}
	if err := s.expireBlocks(now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='бан истёк'`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	st = s.uiStateQ(stateQuery{Section: "policy"})
	if st.err != nil {
		t.Fatal(st.err)
	}
	if len(st.Bans) != 0 {
		t.Fatalf("expired still live %+v", st.Bans)
	}
	for _, a := range st.Alerts {
		if a.BanID == blockID && a.BanState != "expired" {
			t.Fatalf("card %+v", a)
		}
	}
	st = s.uiStateQ(stateQuery{Section: "policy", BanView: "expired", BanIP: "217.60.76", BanSince: now - 86400000})
	if len(st.Bans) != 1 || st.Bans[0].ID != blockID || st.Bans[0].State != "expired" {
		t.Fatalf("history %+v", st.Bans)
	}
	st = s.uiStateQ(stateQuery{Section: "policy", BanView: "expired", BanIP: "198.51.100.9", BanSince: now - 86400000})
	if len(st.Bans) != 0 {
		t.Fatal("ip filter", len(st.Bans))
	}
	st = s.uiStateQ(stateQuery{Section: "policy", BanView: "active", BanID: blockID})
	if len(st.Bans) != 1 || st.Bans[0].ID != blockID {
		t.Fatal("pin", len(st.Bans))
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "203.0.113.77", "h", false, "перебор SSH", "ssh", now)
	}); err != nil {
		t.Fatal(err)
	}
	var sshID string
	if err := s.st.DB.QueryRow(`SELECT block_id FROM blocks WHERE remote_ip='203.0.113.77' AND state='active'`).Scan(&sshID); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { return removeBan(tx, sshID, "adm", now) }); err != nil {
		t.Fatal(err)
	}
	st = s.uiStateQ(stateQuery{Section: "policy", BanView: "removed", BanSince: now - 86400000})
	if len(st.Bans) != 1 || st.Bans[0].ID != sshID || st.Bans[0].State != "removed" {
		t.Fatalf("removed %+v", st.Bans)
	}
	var sshAlert uiAlert
	for _, a := range st.Alerts {
		if a.Rule == "ssh" {
			sshAlert = a
		}
	}
	if sshAlert.BanID != sshID || sshAlert.BanState != "removed" || sshAlert.BanGone == "" {
		t.Fatalf("ssh card %+v", sshAlert)
	}
	// История — добавка: живые баны в ответе остаются, иначе карточки их не найдут.
	if err := s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "198.51.100.20", "h", true, "скан портов", "scan", now)
	}); err != nil {
		t.Fatal(err)
	}
	st = s.uiStateQ(stateQuery{Section: "policy", BanView: "expired", BanIP: "217.60.76", BanSince: now - 86400000})
	var nLive, nOld int
	for _, b := range st.Bans {
		switch b.State {
		case "active":
			nLive++
		case "expired":
			nOld++
		}
	}
	if nLive != 1 || nOld != 1 {
		t.Fatalf("history must keep live bans: live=%d expired=%d %+v", nLive, nOld, st.Bans)
	}
	rows := readUIAudit(&checkedRead{db: s.st.DB}, stateQuery{Action: "ban"})
	var sawScan, sawGone bool
	for _, row := range rows {
		if row.Action == "скан портов" && strings.Contains(row.Object, "217.60.76.226") && strings.Contains(row.Object, "все серверы") {
			sawScan = true
		}
		if row.Action == "бан истёк" && strings.Contains(row.Object, "все серверы") {
			sawGone = true
		}
	}
	if !sawScan || !sawGone {
		t.Fatalf("journal scan=%v gone=%v %+v", sawScan, sawGone, rows)
	}
}
