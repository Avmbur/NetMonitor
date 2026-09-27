package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/store"
)

func insertReportFlow(t *testing.T, s *Server, uid, dir, proto, rip, scope string, lp, rp int, orig, reply, seen int64) {
	t.Helper()
	_, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,local_port,remote_ip,remote_ip_bin,remote_port,remote_scope,origin,received_at_ms,orig_bytes,reply_bytes)
		VALUES(?,?,?,?,?,?,4,?,?,zeroblob(16),?,zeroblob(16),?,?,zeroblob(16),?,?,zeroblob(16),?,?, 'host',?,?,?)`,
		uid, "h", "a", "b", seen, seen, proto, "10.0.0.1", rip, dir, "10.0.0.1", lp, rip, rp, scope, seen, orig, reply)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaxAddrCountsInternetDownload(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`)
	insertReportFlow(t, s, "f1", "out", "tcp", "185.125.190.36", "internet", 41000, 443, 100, 50000, now)
	_, err := s.st.DB.Exec(`INSERT INTO flow_samples(event_id,flow_uid,agent_id,t0_ms,t1_ms,orig_bytes_delta,reply_bytes_delta,orig_packets_delta,reply_packets_delta,bytes_out,bytes_in,pkts_out,pkts_in,quality,observed_at_ms,received_at_ms)
		VALUES('s1','f1','a',?,?,100,50000,1,1,100,50000,1,1,'ok',?,?)`, now-1000, now, now, now)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id=maxaddr", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rep uiReport
	json.Unmarshal(w.Body.Bytes(), &rep)
	if len(rep.Rows) == 0 || rep.Rows[0][0] != "185.125.190.36" {
		t.Fatalf("maxaddr %+v", rep.Rows)
	}
}

func TestRuleHitsUsesRuleName(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`)
	raw := `{"id":"default-ssh","name":"SSH","enabled":true,"action":"allow","match":{"direction":"in","protocol":"tcp","local_port":22}}`
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('default-ssh',1,1,?)`, raw); err != nil {
		t.Fatal(err)
	}
	insertReportFlow(t, s, "ssh1", "in", "tcp", "203.0.113.9", "lan", 22, 53101, 200, 50, now)
	w := httptest.NewRecorder()
	s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id=rulehits", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rep uiReport
	json.Unmarshal(w.Body.Bytes(), &rep)
	found := false
	for _, row := range rep.Rows {
		if len(row) > 0 && row[0] == "SSH" {
			found = true
			if row[1] != "dev-postgres" {
				t.Fatalf("server %q", row[1])
			}
		}
		if len(row) > 0 && looksAuditID(row[0]) {
			t.Fatalf("uuid %q", row[0])
		}
	}
	if !found {
		t.Fatalf("no SSH %+v", rep.Rows)
	}
}

func TestReportCatalogHasNewIDs(t *testing.T) {
	want := []string{"topproc", "newdns", "drops", "rulenone", "longsess", "lanin", "montraf"}
	have := map[string]bool{}
	for _, m := range reportCatalog() {
		have[m.ID] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Fatal("missing", id)
		}
	}
}

func getReport(t *testing.T, s *Server, id string) uiReport {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id="+id, nil))
	if w.Code != 200 {
		t.Fatal(id, w.Code, w.Body.String())
	}
	var rep uiReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestNewReportsFill(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('listen_host','192.168.10.185'),('listen_port','8443')`)
	insertReportFlow(t, s, "p1", "out", "tcp", "185.125.190.36", "internet", 41000, 443, 100, 50000, now)
	if _, err := s.st.DB.Exec(`UPDATE flows SET proc_comm='apt', proc_path='/usr/bin/apt' WHERE flow_uid='p1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO flow_samples(event_id,flow_uid,agent_id,t0_ms,t1_ms,orig_bytes_delta,reply_bytes_delta,orig_packets_delta,reply_packets_delta,bytes_out,bytes_in,pkts_out,pkts_in,quality,observed_at_ms,received_at_ms)
		VALUES('s1','p1','a',?,?,100,50000,1,1,100,50000,1,1,'ok',?,?)`, now-1000, now, now, now); err != nil {
		t.Fatal(err)
	}
	insertReportFlow(t, s, "l1", "in", "tcp", "192.168.10.20", "lan", 22, 53101, 200, 50, now)
	insertReportFlow(t, s, "m1", "out", "tcp", "192.168.10.185", "lan", 41001, 8443, 80, 40, now)
	if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES('h','api.example.test',zeroblob(16),'203.0.113.50',?,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO firewall_events(event_id,host_id,observed_at_ms,received_at_ms,remote_ip,verdict,rule_tag,hits) VALUES('e1','h',?,?,'9.9.9.9','drop','обучение',7)`, now, now); err != nil {
		t.Fatal(err)
	}
	raw := `{"id":"quiet","name":"Тихий","enabled":true,"action":"deny","match":{"direction":"out","protocol":"tcp","remote_port":9}}`
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('quiet',1,2,?)`, raw); err != nil {
		t.Fatal(err)
	}

	top := getReport(t, s, "topproc")
	if len(top.Rows) == 0 || top.Rows[0][0] != "apt" || top.Rows[0][1] != "dev-postgres" {
		t.Fatalf("topproc %+v", top.Rows)
	}
	dns := getReport(t, s, "newdns")
	if len(dns.Rows) == 0 || dns.Rows[0][0] != "api.example.test" || dns.Rows[0][1] != "203.0.113.50" {
		t.Fatalf("newdns %+v", dns.Rows)
	}
	drops := getReport(t, s, "drops")
	if len(drops.Rows) == 0 || drops.Rows[0][0] != "9.9.9.9" || drops.Rows[0][2] != "обучение" || drops.Rows[0][3] != "7" {
		t.Fatalf("drops %+v", drops.Rows)
	}
	none := getReport(t, s, "rulenone")
	found := false
	for _, row := range none.Rows {
		if len(row) > 0 && row[0] == "Тихий" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rulenone %+v", none.Rows)
	}
	long := getReport(t, s, "longsess")
	if len(long.Rows) == 0 {
		t.Fatal("longsess empty")
	}
	lan := getReport(t, s, "lanin")
	if len(lan.Rows) == 0 || lan.Rows[0][0] != "192.168.10.20" || lan.Rows[0][2] != "22" {
		t.Fatalf("lanin %+v", lan.Rows)
	}
	mon := getReport(t, s, "montraf")
	if len(mon.Rows) == 0 || mon.Rows[0][2] != "192.168.10.185" {
		t.Fatalf("montraf %+v", mon.Rows)
	}
}
