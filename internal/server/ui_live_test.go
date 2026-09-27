package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/passwd"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestNTPNameOnUbuntuPoolFlow(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	_, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_port,remote_scope,origin,received_at_ms)
		VALUES('ntp1','h','a','b',?,?,4,'udp','192.168.10.180',zeroblob(16),'185.125.190.121',zeroblob(16),'out','192.168.10.180',zeroblob(16),'185.125.190.121',zeroblob(16),123,'internet','host',?)`, now, now, now)
	if err != nil {
		t.Fatal(err)
	}
	st := s.uiState("", "activity")
	if len(st.Flows) != 1 || st.Flows[0].DNS != "ntp.ubuntu.com" {
		t.Fatalf("ntp dns %+v", st.Flows)
	}
}

func TestProcNameFromPath(t *testing.T) {
	if got := procNameFromPath("/usr/libexec/fwupd/fwupdmgr  uid=0"); got != "fwupdmgr" {
		t.Fatal(got)
	}
	if got := procNameFromPath(""); got != "" {
		t.Fatal(got)
	}
}

func TestCountersAreContactsNotBans(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
		VALUES('f1','h','a','b',?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, now, now, now)
	s.st.DB.Exec(`INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms) VALUES('b1','all','9.9.9.9',zeroblob(16),'both','active','ручной','ui','adm',?)`, now)
	s.st.DB.Exec(`INSERT INTO firewall_events(event_id,host_id,observed_at_ms,received_at_ms,hits) VALUES('e1','h',?, ?, 3)`, now, now)
	st := s.uiState("", "activity")
	if st.Now.Flows != 1 {
		t.Fatal("flows", st.Now.Flows)
	}
	if st.Now.Blocked == 1 && st.Now.Blocked != 3 {
		// blocked is NFLOG hits, not the single ban row
	}
	if st.Now.Blocked != 3 {
		t.Fatal("blocked used bans", st.Now.Blocked)
	}
	if st.Now.Allowed != st.Now.Flows {
		t.Fatal("allowed", st.Now.Allowed, "flows", st.Now.Flows)
	}
}

func TestAgentOfflineNotTrustedOnline(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=1 WHERE host_id='h'`)
	st := s.uiState("", "settings")
	if len(st.Agents) != 1 || st.Agents[0].Online {
		t.Fatal(st.Agents)
	}
	if st.Agents[0].TrustLabel != "нет данных" {
		t.Fatal(st.Agents[0].TrustLabel)
	}
}

func TestPasswordNeedsOldAndAudits(t *testing.T) {
	s, _ := batchFixture(t)
	h, err := passwd.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('adm_password',?)`, h)
	w := httptest.NewRecorder()
	s.handlePassword(w, httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"old":"no","new":"x"}`)))
	if w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handlePassword(w, httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"old":"secret","new":"next"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var n int
	s.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='сменил пароль'`).Scan(&n)
	if n != 1 {
		t.Fatal("audit", n)
	}
}

func TestAlertsInStateAndHistory(t *testing.T) {
	s, cert := batchFixture(t)
	raw, _ := json.Marshal(protocol.ScanPayload{IP: "203.0.113.9", Ports: []int{22, 80, 443, 3306, 8080}})
	sendBatch(t, s, cert, protocol.Event{EventID: "sc", Seq: 1, Kind: "scan", ObservedAtMS: store.NowMS(), Payload: raw})
	st := s.uiState("", "policy")
	if st.Alerts == nil {
		t.Fatal("alerts omitted")
	}
	w := httptest.NewRecorder()
	s.handleAlert(w, httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"id":"missing","op":"history"}`)))
	if w.Code == 200 {
		t.Fatal("missing closed")
	}
}

func TestClosedAlertLeavesTileCatchupKeepsTag(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	_, err := s.st.DB.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,closed_at_ms,severity,summary,backfill)
		VALUES('live','paused_local',1,'h','paused_local/h',?,NULL,'high','бан снят аварийно',0),
		('gone','paused_local',1,'h','paused_local/h-old',?,?, 'high','бан снят аварийно',0),
		('bf','clone',1,'h','clone/h',?,NULL,'high','клон сертификата',1)`, now, now-1000, now-500, now)
	if err != nil {
		t.Fatal(err)
	}
	st := s.uiState("", "policy")
	var live, gone, catchup bool
	for _, a := range st.Alerts {
		if a.ID == "live" {
			live = a.State == "red"
			if a.Hist {
				t.Fatal("live tagged catch-up")
			}
		}
		// Лента: закрытая тревога не исчезает, она жёлтая, пока её не видели.
		if a.ID == "gone" {
			gone = a.State == "yellow"
		}
		if a.ID == "bf" {
			catchup = a.Hist
		}
	}
	if !live || !gone || !catchup {
		t.Fatalf("live=%v gone=%v catchup=%v n=%d", live, gone, catchup, len(st.Alerts))
	}
}

func TestUIStateSectionCuts(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms,ended_at_ms)
		VALUES('h1','h','a','b',?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'8.8.8.8',zeroblob(16),'internet','host',?,?)`, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	act := s.uiStateQ(stateQuery{Section: "activity"})
	if act.History != nil || act.Audit != nil || act.Bans != nil || act.Rules != nil || act.Groups != nil {
		t.Fatalf("activity extra hist=%d audit=%d bans=%d rules=%d groups=%d", len(act.History), len(act.Audit), len(act.Bans), len(act.Rules), len(act.Groups))
	}
	if act.Flows == nil {
		t.Fatal("activity flows")
	}
	lg := s.uiStateQ(stateQuery{Section: "log"})
	if lg.Flows != nil || lg.Bans != nil || lg.Rules != nil {
		t.Fatalf("log extra flows=%d bans=%d rules=%d", len(lg.Flows), len(lg.Bans), len(lg.Rules))
	}
	if lg.History == nil || lg.Audit == nil {
		t.Fatal("log missing")
	}
	for _, f := range lg.History {
		if f.RateKnown {
			t.Fatal("history rate")
		}
	}
	pol := s.uiStateQ(stateQuery{Section: "policy"})
	if pol.History != nil || pol.Flows != nil || pol.Audit != nil {
		t.Fatal("policy extra")
	}
	if pol.Bans == nil || pol.Rules == nil || pol.Never == nil {
		t.Fatal("policy missing")
	}
	has := func(st uiState, k string) bool {
		for _, x := range st.Loaded {
			if x == k {
				return true
			}
		}
		return false
	}
	if !has(act, "flows") || has(act, "history") || has(act, "bans") {
		t.Fatalf("activity loaded %v", act.Loaded)
	}
	if !has(lg, "history") || !has(lg, "audit") || has(lg, "flows") {
		t.Fatalf("log loaded %v", lg.Loaded)
	}
	if !has(pol, "bans") || has(pol, "history") {
		t.Fatalf("policy loaded %v", pol.Loaded)
	}
}

func TestFillServerTrafficFromMinutes(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`INSERT INTO traffic_1m(host_id,bucket_start_ms,direction,remote_scope,bytes_out,bytes_in,samples) VALUES('h',?,'out','internet',100,50,1)`, now); err != nil {
		t.Fatal(err)
	}
	db := &checkedRead{db: s.st.DB}
	servers := []uiServer{{HostID: "h"}}
	fillServerTraffic(db, servers)
	if servers[0].Rx24 != 50 || servers[0].Tx24 != 100 {
		t.Fatalf("rx=%d tx=%d", servers[0].Rx24, servers[0].Tx24)
	}
}

func TestHistoryFilterByAddr(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms,ended_at_ms)
		VALUES('h1','h','a','b',?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'8.8.8.8',zeroblob(16),'internet','host',?,?)`, now, now, now, now)
	st := s.uiStateQ(stateQuery{Section: "log", Addr: "8.8.8.8"})
	if len(st.History) == 0 {
		t.Fatal("filtered out")
	}
	st = s.uiStateQ(stateQuery{Section: "log", Addr: "9.9.9.9"})
	if len(st.History) != 0 {
		t.Fatal("addr leak")
	}
}

func TestReportsCatalogAndMaxAddr(t *testing.T) {
	s, _ := batchFixture(t)
	w := httptest.NewRecorder()
	s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id=maxaddr", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rep uiReport
	json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.ID != "maxaddr" || len(rep.Cols) == 0 {
		t.Fatal(rep)
	}
	w = httptest.NewRecorder()
	s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id=nope", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestSettingsSoundAndKeepStored(t *testing.T) {
	s, _ := batchFixture(t)
	w := httptest.NewRecorder()
	s.handleSaveSettings(w, httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"sound_ask":true,"sound_alert":false,"sound_ask_s":7,"sound_alert_s":15,"samples_n":14,"samples_u":"d","db_max_gb":3}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	st := s.uiState("", "settings")
	if st.Settings["sound_ask"] != "1" || st.Settings["sound_alert"] != "0" || st.Settings["sound_ask_s"] != "7" || st.Settings["sound_alert_s"] != "15" || st.Settings["samples_n"] != "14" || st.Settings["db_max_gb"] != "3" {
		t.Fatal(st.Settings)
	}
	var n int
	s.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action='сохранил настройки'`).Scan(&n)
	if n < 1 {
		t.Fatal("no audit")
	}
}

func TestLiveStateHasNoDemoHosts(t *testing.T) {
	s, _ := batchFixture(t)
	st := s.uiState("", "activity")
	for _, srv := range st.Servers {
		if srv.Name == "web-1" {
			t.Fatal("demo host")
		}
	}
	if st.Alerts == nil || st.Flows == nil {
		t.Fatal("missing live arrays")
	}
	if st.Reports != nil || st.History != nil {
		t.Fatal("activity extra arrays")
	}
}

func TestAgentVersionFromHealth(t *testing.T) {
	s, cert := batchFixture(t)
	q := int64(12)
	raw, _ := json.Marshal(protocol.HealthPayload{Kind: "alive", Version: "0.1.0", QueueBytes: &q, FWBackend: "nftables"})
	sendBatch(t, s, cert, protocol.Event{EventID: "hv", Seq: 10, Kind: "health", ObservedAtMS: store.NowMS(), Payload: raw})
	st := s.uiState("", "settings")
	if st.Agents[0].Version != "0.1.0" {
		t.Fatal(st.Agents[0].Version)
	}
}
