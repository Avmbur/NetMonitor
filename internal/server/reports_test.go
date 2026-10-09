package server

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
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

func TestRemovedReportsStayGone(t *testing.T) {
	s, _ := batchFixture(t)
	gone := []string{"topout", "new24", "rulehits", "noreply", "topproc", "rulenone", "montraf"}
	have := map[string]bool{}
	for _, m := range reportCatalog() {
		have[m.ID] = true
	}
	for _, id := range gone {
		if have[id] {
			t.Fatal("still listed", id)
		}
		w := httptest.NewRecorder()
		s.handleReports(w, httptest.NewRequest("GET", "/ui/api/reports?id="+id, nil))
		if w.Code != 400 {
			t.Fatalf("%s code %d body %s", id, w.Code, w.Body.String())
		}
	}
}

func TestReportCatalogHasKeptIDs(t *testing.T) {
	want := []string{"scanners", "sshfail", "blocked", "persist"}
	have := map[string]bool{}
	for _, m := range reportCatalog() {
		have[m.ID] = true
	}
	if len(have) != len(want) {
		t.Fatalf("catalog %d, want %d", len(have), len(want))
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

func TestScanBanStoresPortsWithoutPacketHistory(t *testing.T) {
	s, cert := batchFixture(t)
	ev := scanEvent("scan-evidence", 1)
	if code, ack := sendBatch(t, s, cert, ev); code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("scan %d %+v", code, ack)
	}
	var stored string
	var seen int64
	if err := s.st.DB.QueryRow(`SELECT scan_ports, scan_seen_ms FROM blocks WHERE remote_ip='203.0.113.50'`).Scan(&stored, &seen); err != nil {
		t.Fatal(err)
	}
	if stored != "22, 80, 443, 3306, 8080" || seen != ev.ObservedAtMS {
		t.Fatalf("stored %q seen %d event %d", stored, seen, ev.ObservedAtMS)
	}
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms) VALUES('oldscan','all','198.51.100.40',zeroblob(16),'both','active','скан портов','scan','auto',?)`, now); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{11, 7, 9} {
		if _, err := s.st.DB.Exec(`INSERT INTO firewall_events(event_id,host_id,observed_at_ms,received_at_ms,direction,local_port,remote_ip,hits) VALUES(?,?,?,?,'in',?,'198.51.100.40',1)`, "old-"+strconv.Itoa(port), "h", now-1000, now, port); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.st.DB.Exec(`INSERT INTO firewall_events(event_id,host_id,observed_at_ms,received_at_ms,direction,local_port,remote_ip,hits) VALUES('decoy','h',?,?,'in',1,'203.0.113.50',1)`, now-1000, now); err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{}
	for _, row := range getReport(t, s, "scanners").Rows {
		if len(row) > 0 {
			rows[row[0]] = row
		}
	}
	got := rows["203.0.113.50"]
	if len(got) < 5 || got[2] != "5" || got[3] != "22, 80, 443, 3306, 8080" || got[4] != "бан" {
		t.Fatalf("stored report %+v", got)
	}
	old := rows["198.51.100.40"]
	if len(old) < 5 || old[2] != "\u2014" || old[3] != "\u2014" {
		t.Fatalf("fallback report %+v", old)
	}
}
