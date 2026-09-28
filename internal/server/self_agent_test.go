package server

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/policy"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func TestFindMonitorAgentByNameAndListen(t *testing.T) {
	s, _ := batchFixture(t)
	if _, ok, err := s.findMonitorAgent(); err != nil || ok {
		t.Fatal("empty", ok, err)
	}
	s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('listen_host','192.168.10.185')`)
	s.st.DB.Exec(`UPDATE agents SET last_src_ip='192.168.10.185' WHERE agent_id='a'`)
	ag, ok, err := s.findMonitorAgent()
	if err != nil || !ok || ag.AgentID != "a" {
		t.Fatal(ag, ok, err)
	}
}

func TestInstallSelfTrustsLearn(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('listen_host','192.168.10.185'),('listen_port','8443')`)
	s.cfg.ListenHost = "192.168.10.185"
	s.cfg.ListenPort = 8443
	b, err := tlsutil.LoadOrCreateCA(filepath.Join(s.cfg.DataDir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	s.bundle = b
	selfInstallWait = 200 * time.Millisecond
	t.Cleanup(func() {
		selfInstallHook = nil
		selfInstallWait = 45 * time.Second
	})
	selfInstallHook = func(srv *Server, endpoint, pin, token string) error {
		if endpoint == "" || pin == "" || token == "" {
			t.Fatal(endpoint, pin, token)
		}
		hash := idgen.TokenHash(token)
		return srv.st.Update(func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES('hm','dev-monitoring',1,1)`); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,display_name,first_seen_ms,last_src_ip) VALUES('am','hm','fp-m','pending','dev-monitoring',1,'192.168.10.185')`); err != nil {
				return err
			}
			_, err := tx.Exec(`UPDATE enroll_tokens SET used_at_ms=1, used_by_agent='am' WHERE token_hash=?`, hash)
			return err
		})
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/api/install-self", bytes.NewBufferString("{}"))
	req.Host = "192.168.10.185:8443"
	w := httptest.NewRecorder()
	s.handleInstallSelf(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var trust, name string
	s.st.DB.QueryRow(`SELECT trust_state, display_name FROM agents WHERE agent_id='am'`).Scan(&trust, &name)
	if trust != "trusted" || name != "монитор" {
		t.Fatal(trust, name)
	}
	c, err := readControl(s.st.DB, "hm")
	if err != nil || c.Mode != "learn" {
		t.Fatal(c, err)
	}
	st := s.uiState("", "activity")
	var saw bool
	for _, srv := range st.Servers {
		if srv.Monitor {
			saw = true
			if srv.Name != "монитор" || srv.HostID != "hm" {
				t.Fatal(srv)
			}
		}
	}
	if !saw {
		t.Fatal(st.Servers)
	}
	w2 := httptest.NewRecorder()
	s.handleInstallSelf(w2, httptest.NewRequest(http.MethodPost, "/ui/api/install-self", nil))
	if w2.Code != 409 {
		t.Fatal(w2.Code, w2.Body.String())
	}
	rs, err := hostRules(s.st.DB, "hm")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]policy.Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	port := byID[monitorRulePort]
	icmp := byID[monitorRuleICMP]
	ssh := byID[monitorRuleSSH]
	if !strings.Contains(port.Name, "руками не трогать") || port.Match.AnyPort != 8443 {
		t.Fatal(port)
	}
	if !strings.Contains(icmp.Name, "руками не трогать") || icmp.Match.Protocol != "icmp" {
		t.Fatal(icmp)
	}
	if !strings.Contains(ssh.Name, "руками не трогать") || ssh.Match.AnyPort != 22 {
		t.Fatal(ssh)
	}
	whois := byID[monitorRuleWhois]
	if !strings.Contains(whois.Name, "whois") || whois.Match.RemotePort != 43 || whois.Match.Direction != "out" {
		t.Fatal(whois)
	}
	for _, r := range []policy.Rule{port, icmp, ssh} {
		if r.Action != "allow" || len(r.Hosts) != 1 || r.Hosts[0] != "hm" {
			t.Fatal(r)
		}
		if len(r.Match.Networks) == 0 {
			t.Fatal("lan networks", r)
		}
	}
	park, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range park {
		if strings.HasPrefix(r.ID, "monitor-svc-") {
			t.Fatal("park host got monitor service rule", r)
		}
	}
}

func TestMonitorServiceRulesFollowLANAndCloseQuestions(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('listen_host','192.168.10.185'),('listen_port','8443'),('lan','10.0.0.0/8'),('monitor_host_id','h')`)
	if err := s.st.Update(func(tx *sql.Tx) error { return s.syncMonitorServiceRules(tx, "h") }); err != nil {
		t.Fatal(err)
	}
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var port policy.Rule
	for _, r := range rs {
		if r.ID == monitorRulePort {
			port = r
		}
	}
	if len(port.Match.Networks) != 1 || port.Match.Networks[0] != "10.0.0.0/8" {
		t.Fatal(port.Match.Networks)
	}
	now := store.NowMS()
	s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,direction,protocol,remote_ip,local_port,remote_port,status,opened_at_ms,last_seen_ms,repeats)
		VALUES('q1','h','k1','in','tcp','10.1.2.3',8443,0,'open',?, ?,1)`, now, now)
	s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,direction,protocol,remote_ip,local_port,remote_port,status,opened_at_ms,last_seen_ms,repeats)
		VALUES('q2','h','k2','in','icmp','10.9.9.9',0,0,'open',?, ?,1)`, now, now)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('lan','192.168.0.0/16'),('listen_port','9443')`)
	if err := s.st.Update(func(tx *sql.Tx) error { return s.syncMonitorServiceRules(tx, "h") }); err != nil {
		t.Fatal(err)
	}
	rs, err = hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == monitorRulePort {
			if r.Match.AnyPort != 9443 || r.Match.Networks[0] != "192.168.0.0/16" {
				t.Fatal(r.Match)
			}
		}
		if r.ID == monitorRuleICMP && (len(r.Match.Networks) != 1 || r.Match.Networks[0] != "192.168.0.0/16") {
			t.Fatal(r.Match.Networks)
		}
	}
	var st1, st2 string
	s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id='q1'`).Scan(&st1)
	s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id='q2'`).Scan(&st2)
	if st1 != "open" {
		t.Fatal("q1 should stay open after LAN moved off 10/8", st1)
	}
	if st2 != "open" {
		t.Fatal("q2 should stay open after LAN moved off 10/8", st2)
	}
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('lan','10.0.0.0/8'),('listen_port','8443')`)
	s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,direction,protocol,remote_ip,local_port,remote_port,status,opened_at_ms,last_seen_ms,repeats)
		VALUES('q3','h','k3','in','tcp','10.1.2.3',8443,0,'open',?, ?,1)`, now, now)
	if err := s.st.Update(func(tx *sql.Tx) error { return s.syncMonitorServiceRules(tx, "h") }); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id='q3'`).Scan(&st1)
	if st1 != "answered" {
		t.Fatal("q3", st1)
	}
}

func TestMonitorSSHPortFromInventory(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('lan','192.168.0.0/16'),('listen_port','8443'),('monitor_host_id','h')`)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('inventory:h', '{"kind":"alive","ssh_port":2222}')`)
	if err := s.st.Update(func(tx *sql.Tx) error { return s.syncMonitorServiceRules(tx, "h") }); err != nil {
		t.Fatal(err)
	}
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var ssh policy.Rule
	for _, r := range rs {
		if r.ID == monitorRuleSSH {
			ssh = r
		}
	}
	if ssh.Match.AnyPort != 2222 {
		t.Fatal(ssh.Match)
	}
	if err := s.st.Update(func(tx *sql.Tx) error { return s.syncMonitorServiceRules(tx, "h") }); err != nil {
		t.Fatal(err)
	}
	var ver int64
	s.st.DB.QueryRow(`SELECT version FROM policy_rules WHERE rule_id=?`, monitorRuleSSH).Scan(&ver)
	if ver != 1 {
		t.Fatal("unchanged ssh rule bumped", ver)
	}
}

func TestParseInstallCmd(t *testing.T) {
	ep, pin, tok, err := parseInstallCmd(`curl -fsSk --pinnedpubkey sha256//abc https://192.168.10.185:8443/install/agent.sh | sudo sh -s -- --monitor 192.168.10.185:8443 --pin sha256//abc --token deadbeef`)
	if err != nil || ep != "192.168.10.185:8443" || pin != "sha256//abc" || tok != "deadbeef" {
		t.Fatal(ep, pin, tok, err)
	}
}

func TestUpdateRuleOpensHTTPSOnlyForNetMonitorServices(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.ensureUpdateRule(); err != nil {
		t.Fatal(err)
	}
	var rev int64
	s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev)
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var r policy.Rule
	for _, x := range rs {
		if x.ID == parkRuleUpdate {
			r = x
		}
	}
	if r.Action != "allow" || r.Hosts != nil || r.Match.Direction != "out" || r.Match.Protocol != "tcp" || r.Match.RemotePort != 443 || len(r.Match.Bindings) != 3 {
		t.Fatal(r)
	}
	if !strings.Contains(r.Name, "служебные · обновления") || !isServiceRuleID(r.ID) {
		t.Fatal(r.Name)
	}
	if err := policy.Executable(r); err != nil || policy.Inert(r) {
		t.Fatal("rule does not execute", err)
	}
	if err := s.ensureUpdateRule(); err != nil {
		t.Fatal(err)
	}
	var again int64
	s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&again)
	if again != rev {
		t.Fatal("unchanged rule bumped policy", rev, again)
	}
}