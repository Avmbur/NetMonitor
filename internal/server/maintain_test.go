package server

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netmonitor/internal/tlsutil"
)

func TestCleanStatsKeepsPolicy(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('r',1,1,'{}')`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO collector_health(event_id,host_id,observed_at_ms,received_at_ms,kind) VALUES('e','h',1,1,'gap')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action) VALUES('au',1,'adm','тест')`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO blocks(block_id,scope_kind,state,reason,source,created_by,created_at_ms) VALUES('live','all','active','manual','manual','adm',1),('dead','all','expired','manual','manual','adm',2)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,last_seen_ms,status) VALUES('open-q','h','d1',1,1,'open'),('old-q','h','d2',1,1,'closed')`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,closed_at_ms,severity,summary) VALUES('open-a','r',1,'h','k1',1,NULL,'high','open'),('old-a','r',1,'h','k2',1,2,'high','closed')`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES('h','example.test',zeroblob(16),'203.0.113.9',1,1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/api/db-clean", strings.NewReader(`{"confirm":true,"keep_mb":10}`))
	w := httptest.NewRecorder()
	s.handleDBClean(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("floor %d %s", w.Code, w.Body.String())
	}
	res, err := s.cleanDown(1)
	if err != nil {
		t.Fatal(err)
	}
	if res.After < 1 {
		t.Fatalf("result %+v", res)
	}
	var health, rules, agents, audit, live, dead, openQ, oldQ, openA, oldA, dns int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM collector_health`).Scan(&health); err != nil || health != 1 {
		t.Fatalf("health %d %v", health, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM dns_seen`).Scan(&dns); err != nil || dns != 1 {
		t.Fatalf("dns %d %v", dns, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM policy_rules`).Scan(&rules); err != nil || rules != 1 {
		t.Fatalf("rules %d %v", rules, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&agents); err != nil || agents != 1 {
		t.Fatalf("agents %d %v", agents, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&audit); err != nil || audit != 0 {
		t.Fatalf("audit %d %v", audit, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM blocks WHERE block_id='live'`).Scan(&live); err != nil || live != 1 {
		t.Fatalf("live ban %d %v", live, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM blocks WHERE block_id='dead'`).Scan(&dead); err != nil || dead != 0 {
		t.Fatalf("dead ban %d %v", dead, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM learn_questions WHERE question_id='open-q'`).Scan(&openQ); err != nil || openQ != 1 {
		t.Fatalf("open question %d %v", openQ, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM learn_questions WHERE question_id='old-q'`).Scan(&oldQ); err != nil || oldQ != 0 {
		t.Fatalf("old question %d %v", oldQ, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE alert_id='open-a'`).Scan(&openA); err != nil || openA != 1 {
		t.Fatalf("open alert %d %v", openA, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE alert_id='old-a'`).Scan(&oldA); err != nil || oldA != 0 {
		t.Fatalf("old alert %d %v", oldA, err)
	}
}

func TestCleanReportsSizeAfterCheckpoint(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<4000)
INSERT INTO audit_log(audit_id,at_ms,actor,action,object) SELECT 'au'||i,i,'adm','тест',hex(randomblob(1024)) FROM n`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := s.cleanDown(1)
	if err != nil {
		t.Fatal(err)
	}
	if wal := fileSize(s.st.Path() + "-wal"); wal != 0 {
		t.Fatalf("журнал после очистки %d", wal)
	}
	if res.After != fileSize(s.st.Path()) || res.After >= res.Now {
		t.Fatalf("result %+v file %d", res, fileSize(s.st.Path()))
	}
}

func TestRemoveMonitorQueuesAgents(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('b','h','fp-b','pending',1)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('q','h','fp-q','quarantined',1)`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('c','h','fp-c','revoked',1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	wait, err := s.requestMonitorRemoval(true, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if wait != 45 {
		t.Fatalf("wait %d", wait)
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE kind='uninstall' AND agent_id='a'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("uninstall trusted %d %v", n, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE kind='uninstall' AND agent_id IN ('b','q')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("uninstall waiting %d %v", n, err)
	}
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE kind='uninstall' AND agent_id='c'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("uninstall revoked %d %v", n, err)
	}
	raw, err := os.ReadFile(s.cfg.DataDir + "/remove.request")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "agents=1") || !strings.Contains(text, "wait=45") {
		t.Fatalf("request %q", text)
	}
	wait, err = s.requestMonitorRemoval(false, "192.0.2.1")
	if err != nil || wait != 0 {
		t.Fatalf("second %d %v", wait, err)
	}
	raw, err = os.ReadFile(s.cfg.DataDir + "/remove.request")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "agents=1") || !strings.Contains(string(raw), "agents=0") {
		t.Fatalf("request %q", raw)
	}
}

func TestRebindRejectsForeignCA(t *testing.T) {
	s, _ := batchFixture(t)
	mon, err := tlsutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.bundle = mon
	other, err := tlsutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pemCert, _, _, err := other.IssueClient("stranger")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hello := httptest.NewRequest(http.MethodPost, "/v1/rebind", strings.NewReader(`{"hostname":"stranger"}`))
	hello.RemoteAddr = "192.0.2.9:9"
	hello.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleRebind(w, hello)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("foreign %d %s", w.Code, w.Body.String())
	}
	if len(s.formerAgents()) != 0 {
		t.Fatalf("чужой сертификат попал в список: %+v", s.formerAgents())
	}
}

func TestRebindLetsOldAgentEnroll(t *testing.T) {
	s, _ := batchFixture(t)
	mon, err := tlsutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.bundle = mon
	pemCert, _, fp, err := mon.IssueClient("old-box")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hello := httptest.NewRequest(http.MethodPost, "/v1/rebind", strings.NewReader(`{"hostname":"old-box","agent_id":"old"}`))
	hello.RemoteAddr = "192.0.2.8:9"
	hello.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleRebind(w, hello)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("hello %d %s", w.Code, w.Body.String())
	}
	if _, err := s.agentFromTLS(hello); err == nil || !strings.Contains(err.Error(), "неизвестный сертификат") {
		t.Fatalf("foreign cert accepted: %v", err)
	}
	if err := s.approveRebind("192.0.2.8"); err != nil {
		t.Fatal(err)
	}
	if err := s.approveRebind("192.0.2.8"); err != nil {
		t.Fatal(err)
	}
	var tokens int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM enroll_tokens WHERE used_at_ms IS NULL`).Scan(&tokens); err != nil || tokens != 1 {
		t.Fatalf("tokens %d %v", tokens, err)
	}
	w = httptest.NewRecorder()
	s.handleRebind(w, hello)
	var offer rebindOffer
	if err := json.NewDecoder(w.Body).Decode(&offer); err != nil {
		t.Fatal(err)
	}
	if offer.Status != "ready" || offer.Token == "" || !strings.HasPrefix(offer.Pin, "sha256//") {
		t.Fatalf("offer %+v", offer)
	}
	bad := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"token":"`+offer.Token+`","hostname":"old-box"}`))
	bad.RemoteAddr = "192.0.2.9:1"
	bw := httptest.NewRecorder()
	s.handleEnroll(bw, bad)
	if bw.Code == 200 {
		t.Fatal("token worked without the old certificate")
	}
	ok := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"token":"`+offer.Token+`","hostname":"old-box"}`))
	ok.RemoteAddr = "192.0.2.8:9"
	ok.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	ow := httptest.NewRecorder()
	s.handleEnroll(ow, ok)
	if ow.Code != 200 {
		t.Fatalf("enroll %d %s", ow.Code, ow.Body.String())
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents WHERE display_name='old-box' AND trust_state='pending'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("pending %d %v", n, err)
	}
	if got := s.readyRebindToken(fp); got != "" {
		t.Fatalf("token still offered %s", got)
	}
	if left := s.formerAgents(); len(left) != 0 {
		t.Fatalf("строка осталась: %+v", left)
	}
}

func TestRestartDropsUnusedRebindToken(t *testing.T) {
	s, _ := batchFixture(t)
	mon, err := tlsutil.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.bundle = mon
	pemCert, _, fp, err := mon.IssueClient("old-box")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hello := httptest.NewRequest(http.MethodPost, "/v1/rebind", strings.NewReader(`{"hostname":"old-box"}`))
	hello.RemoteAddr = "192.0.2.8:9"
	hello.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleRebind(w, hello)
	if err := s.approveRebind("192.0.2.8"); err != nil {
		t.Fatal(err)
	}
	token := s.readyRebindToken(fp)
	if token == "" {
		t.Fatal("нет токена")
	}
	if err := s.dropUnusedRebind(); err != nil {
		t.Fatal(err)
	}
	s.rebindTok = nil
	w = httptest.NewRecorder()
	s.handleRebind(w, hello)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("after restart %d %s", w.Code, w.Body.String())
	}
	stale := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"token":"`+token+`","hostname":"old-box"}`))
	stale.RemoteAddr = "192.0.2.8:9"
	stale.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	sw := httptest.NewRecorder()
	s.handleEnroll(sw, stale)
	if sw.Code == 200 {
		t.Fatal("погашенный токен принят")
	}
}
