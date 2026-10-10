package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func ruleRequest(t *testing.T, s *Server, body string, want int) policy.Rule {
	t.Helper()
	w := httptest.NewRecorder()
	s.handlePolicyRule(w, httptest.NewRequest("POST", "/ui/api/rule", bytes.NewBufferString(body)))
	if w.Code != want {
		t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
	}
	var r policy.Rule
	if want == 200 {
		if e := json.Unmarshal(w.Body.Bytes(), &r); e != nil {
			t.Fatal(e)
		}
	}
	return r
}
func TestExactPolicyScopeVersionAndQuestion(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2'),('h3')")
	r := ruleRequest(t, s, `{"kind":"allow","ip":"1.1.1.1","proto":"tcp","direction":"out","port":80,"hosts":["h","h2"]}`, 200)
	for _, host := range []string{"h", "h2", "h3"} {
		rs, e := hostRules(s.st.DB, host)
		if e != nil {
			t.Fatal(e)
		}
		_, hit := policy.Evaluate(rs, host, policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "1.1.1.1", RemotePort: 80}, store.NowMS())
		if hit != (host != "h3") {
			t.Fatal("scope expanded", host, rs)
		}
		for _, c := range []policy.Contact{{Direction: "out", Protocol: "tcp", RemoteIP: "1.1.1.1", RemotePort: 443}, {Direction: "out", Protocol: "udp", RemoteIP: "1.1.1.1", RemotePort: 80}, {Direction: "in", Protocol: "tcp", RemoteIP: "1.1.1.1", RemotePort: 80}} {
			if _, hit := policy.Evaluate(rs, host, c, store.NowMS()); hit {
				t.Fatal("condition lost", host, c)
			}
		}
	}
	raw, _ := json.Marshal(map[string]any{"id": r.ID, "version": r.Version, "name": "changed", "kind": "deny", "hosts": []string{"h2"}, "proto": "tcp", "port": 80, "portSide": "local", "direction": "in"})
	updated := ruleRequest(t, s, string(raw), 200)
	if updated.Version != 2 {
		t.Fatal(updated)
	}
	ruleRequest(t, s, string(raw), 400)
	ruleRequest(t, s, `{"kind":"allow","hosts":[]}`, 400)
	ruleRequest(t, s, `{"kind":"allow","process":"/usr/bin/python3"}`, 400)
	ruleRequest(t, s, `{"kind":"allow","when":"once"}`, 400)
	ruleRequest(t, s, `{"kind":"allow","process":"/usr/bin/curl","bindings":[{"host":"h","path":"/usr/bin/curl","uid":1000}]}`, 400)
	rs, _ := hostRules(s.st.DB, "h")
	if len(rs) != 0 {
		t.Fatal("old scope remained")
	}
	var count int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&count)
	if count != 0 {
		t.Fatal("deny became manual ban")
	}
}
func TestAllowProtectsOnlyMatchingScanAttempts(t *testing.T) {
	s, cert := batchFixture(t)
	ruleRequest(t, s, `{"kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":443,"hosts":["h"]}`, 200)
	makeScan := func(id string, seq int64, ports []int) protocol.Event {
		p := protocol.ScanPayload{IP: "203.0.113.50", Ports: ports}
		for _, pnum := range ports {
			p.Attempts = append(p.Attempts, protocol.ScanAttempt{Protocol: "tcp", Port: pnum})
		}
		raw, _ := json.Marshal(p)
		return protocol.Event{EventID: id, Seq: seq, Kind: "scan", ObservedAtMS: store.NowMS(), Payload: raw}
	}
	sendBatch(t, s, cert, makeScan("five", 1, []int{22, 80, 443, 3306, 8080}))
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&n)
	if n != 0 {
		t.Fatal("allowed attempt counted")
	}
	sendBatch(t, s, cert, makeScan("six", 2, []int{22, 80, 443, 3306, 8080, 8444}))
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&n)
	if n != 1 {
		t.Fatal("other ports became immune")
	}
}
func TestQuestionTogetherDoesNotExpandHosts(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	for _, h := range []string{"h", "h2"} {
		_, e := s.st.DB.Exec("INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,local_port,remote_port,status) VALUES(?,?,?,1,1,1,'in','tcp','1.1.1.1',443,57000,'open')", h, h, h)
		if e != nil {
			t.Fatal(e)
		}
	}
	ruleRequest(t, s, `{"kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":443,"hosts":["h"],"together":true,"question_id":"h"}`, 200)
	var a, b string
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE question_id='h'").Scan(&a)
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE question_id='h2'").Scan(&b)
	if a != "answered" || b != "open" {
		t.Fatal(a, b)
	}
}

func TestOrdinaryAllowProtectsSSHUntilDisabled(t *testing.T) {
	s, cert := batchFixture(t)
	r := ruleRequest(t, s, `{"name":"SSH allow","kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":22,"networks":["203.0.113.61/32"],"hosts":["h"]}`, 200)
	for seq := int64(1); seq <= 6; seq++ {
		raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.61", User: "nobody", Note: "Failed password"})
		sendBatch(t, s, cert, protocol.Event{EventID: fmt.Sprintf("ssh-%d", seq), Seq: seq, Kind: "ssh", ObservedAtMS: store.NowMS(), Payload: raw})
	}
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM ssh_failures").Scan(&n)
	if n != 0 || s.ssh.count("h", "203.0.113.61", store.NowMS()) != 6 {
		t.Fatal(n, s.ssh.count("h", "203.0.113.61", store.NowMS()))
	}
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&n)
	if n != 0 {
		t.Fatal("matching ordinary allow did not protect")
	}
	body, _ := json.Marshal(map[string]any{"id": r.ID, "version": r.Version, "enabled": false, "kind": "allow", "proto": "tcp", "direction": "in", "portSide": "local", "port": 22, "hosts": []string{"h"}})
	ruleRequest(t, s, string(body), 200)
	raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.61", User: "nobody", Note: "Failed password"})
	sendBatch(t, s, cert, protocol.Event{EventID: "ssh-disabled", Seq: 7, Kind: "ssh", ObservedAtMS: store.NowMS(), Payload: raw})
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&n)
	if n != 1 {
		t.Fatal("disabled rule still protects")
	}
}

func TestStarterSSHAllowDoesNotShieldBruteForce(t *testing.T) {
	s, cert := batchFixture(t)
	ruleRequest(t, s, `{"name":"SSH отовсюду","kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":22,"hosts":["h"]}`, 200)
	for seq := int64(1); seq <= 6; seq++ {
		raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.62", User: "nobody", Note: "Failed password"})
		sendBatch(t, s, cert, protocol.Event{EventID: fmt.Sprintf("brute-%d", seq), Seq: seq, Kind: "ssh", ObservedAtMS: store.NowMS(), Payload: raw})
	}
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE source='ssh' AND remote_ip='203.0.113.62'").Scan(&n)
	if n != 1 {
		t.Fatal("blanket allow on :22 swallowed the brute force ban", n)
	}
}

func TestStarterSSHFollowsHostSSHPorts(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('inventory:h', '{"kind":"alive","ssh_port":2222,"ssh_ports":[22,2222,2223]}'),
		('inventory:h2', '{"kind":"alive","ssh_port":2200}')`)
	s.st.DB.Exec(`INSERT OR REPLACE INTO policy_rules(rule_id,version,sort_order,payload) VALUES('default-ssh',1,1000,
		'{"id":"default-ssh","name":"SSH","enabled":true,"action":"allow","match":{"direction":"in","protocol":"tcp","local_port":22}}')`)
	ports := func(host string) []int {
		rs, err := hostRules(s.st.DB, host)
		if err != nil {
			t.Fatal(err)
		}
		var out []int
		for _, r := range rs {
			if strings.HasPrefix(r.ID, policy.StarterSSH) {
				out = append(out, r.Match.LocalPort)
			}
		}
		return out
	}
	if p := ports("h"); !slices.Equal(p, []int{22, 2222, 2223}) {
		t.Fatal("every sshd port on h", p)
	}
	if p := ports("h2"); !slices.Equal(p, []int{22, 2200}) {
		t.Fatal("agent reporting one port", p)
	}
	if p := ports("h3"); !slices.Equal(p, []int{22}) {
		t.Fatal("no report yet", p)
	}
}

func TestAllowOnNonStandardSSHPortProtects(t *testing.T) {
	s, cert := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('inventory:h', '{"kind":"alive","ssh_port":2222}')`)
	ruleRequest(t, s, `{"name":"SSH allow","kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":2222,"networks":["203.0.113.63/32"],"hosts":["h"]}`, 200)
	for seq := int64(1); seq <= 6; seq++ {
		raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.63", User: "nobody", Note: "Failed password"})
		sendBatch(t, s, cert, protocol.Event{EventID: fmt.Sprintf("ssh2222-%d", seq), Seq: seq, Kind: "ssh", ObservedAtMS: store.NowMS(), Payload: raw})
	}
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&n)
	if n != 0 {
		t.Fatal("allow on the host's sshd port did not protect", n)
	}
}

func bindingHits(t *testing.T, s *Server, host string, c policy.Contact) bool {
	t.Helper()
	rs, err := hostRules(s.st.DB, host)
	if err != nil {
		t.Fatal(err)
	}
	c.Host = host
	d, ok := policy.Evaluate(rs, host, c, store.NowMS())
	return ok && d.Action == "allow"
}

// Container and path bindings are not portable: on several servers they stay
// on the server where the process was seen.
func TestProcessBindingStaysOnObservedHost(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	ct := "system.slice/docker-0123456789ab.scope"
	r := ruleRequest(t, s, `{"kind":"allow","process":"app","proto":"tcp","direction":"out","port":80,"hosts":["h","h2"],"bindings":[{"host":"h","name":"app","cgroup":"`+ct+`"}]}`, 200)
	if len(r.Match.Bindings) != 1 || r.Match.Bindings[0].Host != "h" {
		t.Fatal(r.Match.Bindings)
	}
	c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "1.2.3.4", RemotePort: 80, Cgroup: ct}
	if !bindingHits(t, s, "h", c) {
		t.Fatal("observed host missed")
	}
	if bindingHits(t, s, "h2", c) {
		t.Fatal("container cgroup expanded to a host without a saved binding")
	}
	body, _ := json.Marshal(map[string]any{"id": r.ID, "version": r.Version, "kind": "allow", "process": "app", "proto": "tcp", "direction": "out", "port": 80, "hosts": []string{"h", "h2"}, "bindings": r.Match.Bindings})
	ruleRequest(t, s, string(body), 200)
	if bindingHits(t, s, "h2", c) {
		t.Fatal("server change invented a binding")
	}
	nested := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "1.2.3.4", RemotePort: 81, Cgroup: "system.slice/system-getty.slice/getty@tty1.service"}
	ruleRequest(t, s, `{"kind":"allow","process":"getty","proto":"tcp","direction":"out","port":81,"ip":"1.2.3.4","hosts":"all","bindings":[{"host":"h","name":"getty","cgroup":"`+nested.Cgroup+`"}]}`, 200)
	if !bindingHits(t, s, "h", nested) || bindingHits(t, s, "h2", nested) {
		t.Fatal("nested service binding left its host")
	}
}

// Антон, 10.10.2026: «все серверы · nmagent» из вопроса сохранялось с сервером
// вопроса и действовало только там; каждый следующий сервер спрашивал снова, а
// новое правило не считалось дублем. Служба systemd на нескольких серверах
// теперь действует на всех выбранных, а одинаковое правило отклоняется.
func TestSystemServiceBindingCoversChosenHosts(t *testing.T) {
	s, _ := batchFixture(t)
	for _, h := range []string{"h2", "h3"} {
		s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES(?)", h)
	}
	ask := func(host, scope, except string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		body := `{"kind":"allow","process":"cgroup=system.slice/nmagent.service","proto":"tcp","direction":"out","port":443,"ip":"185.199.111.133","hosts":` + scope + `,"except":` + except + `,"bindings":[{"host":"` + host + `","name":"nmagent","cgroup":"system.slice/nmagent.service"}]}`
		s.handlePolicyRule(w, httptest.NewRequest("POST", "/ui/api/rule", bytes.NewBufferString(body)))
		return w
	}
	c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "185.199.111.133", RemotePort: 443, Cgroup: "system.slice/nmagent.service"}
	if w := ask("h", `"all"`, `["h3"]`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !bindingHits(t, s, "h", c) || !bindingHits(t, s, "h2", c) {
		t.Fatal("service rule missing on a chosen host")
	}
	if bindingHits(t, s, "h3", c) {
		t.Fatal("exception ignored")
	}
	other := c
	other.Cgroup = "system.slice/nmserver.service"
	if bindingHits(t, s, "h2", other) {
		t.Fatal("service binding widened to another service")
	}
	if w := ask("h2", `"all"`, `["h3"]`); w.Code != 400 || !strings.Contains(w.Body.String(), "уже есть") {
		t.Fatal("same rule from another host's question", w.Code, w.Body.String())
	}
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM policy_rules WHERE payload LIKE '%nmagent.service%' AND rule_id NOT LIKE '%svc-%'").Scan(&n)
	if n != 1 {
		t.Fatal("rules", n)
	}
	// Один сервер: привязка остаётся на нём.
	w := ask("h3", `["h3"]`, `[]`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var one policy.Rule
	json.Unmarshal(w.Body.Bytes(), &one)
	if len(one.Match.Bindings) != 1 || one.Match.Bindings[0].Host != "h3" {
		t.Fatal(one.Match.Bindings)
	}
	// Повторное сохранение на нескольких серверах не возвращает сервер вопроса.
	body, _ := json.Marshal(map[string]any{"id": one.ID, "version": one.Version, "kind": "allow", "process": "cgroup=system.slice/nmagent.service", "proto": "tcp", "direction": "out", "port": 443, "ip": "185.199.111.133", "hosts": []string{"h2", "h3"}, "bindings": one.Match.Bindings})
	two := ruleRequest(t, s, string(body), 200)
	if len(two.Match.Bindings) != 1 || two.Match.Bindings[0].Host != "" {
		t.Fatal(two.Match.Bindings)
	}
	if !bindingHits(t, s, "h3", c) {
		t.Fatal("edited rule lost its host")
	}
}

// Жека, #Ж61: переключатель «вкл» шлёт правило целиком и расширял старое
// «все серверы · nmagent», привязанное к одному серверу, на все.
func TestToggleKeepsOldHostBoundRule(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	old := policy.Rule{ID: "old19", Name: "все серверы · nmagent", Version: 1, Enabled: true, Action: "allow", Match: policy.Match{
		Direction: "out", Protocol: "tcp", RemotePort: 443, Networks: []string{"185.199.111.133/32"}, Process: "cgroup=system.slice/nmagent.service",
		Bindings: []policy.Binding{{Host: "h", Name: "nmagent", Cgroup: "system.slice/nmagent.service"}}}}
	raw, _ := json.Marshal(old)
	if _, err := s.st.DB.Exec("INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES(?,?,?,?)", old.ID, 1, 0, string(raw)); err != nil {
		t.Fatal(err)
	}
	c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "185.199.111.133", RemotePort: 443, Cgroup: "system.slice/nmagent.service"}
	toggle := func(version int64, on bool) policy.Rule {
		body, _ := json.Marshal(map[string]any{"id": old.ID, "version": version, "name": old.Name, "kind": "allow", "enabled": on,
			"process": old.Match.Process, "proto": "tcp", "direction": "out", "portSide": "remote", "port": "443", "addr": "185.199.111.133/32",
			"networks": old.Match.Networks, "hosts": "all", "except": []string{}, "bindings": old.Match.Bindings})
		return ruleRequest(t, s, string(body), 200)
	}
	r := toggle(1, false)
	r = toggle(r.Version, true)
	if len(r.Match.Bindings) != 1 || r.Match.Bindings[0].Host != "h" {
		t.Fatal("toggle rewrote bindings", r.Match.Bindings)
	}
	if !bindingHits(t, s, "h", c) || bindingHits(t, s, "h2", c) {
		t.Fatal("toggle changed where the rule acts")
	}
}

// Жека, #Ж61: служба переносилась на несколько серверов, но не на другой один.
func TestServiceBindingMovesToSingleHost(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	r := ruleRequest(t, s, `{"kind":"allow","process":"cgroup=system.slice/nginx.service","proto":"tcp","direction":"out","port":80,"ip":"1.2.3.4","hosts":["h"],"bindings":[{"host":"h","name":"nginx","cgroup":"system.slice/nginx.service"}]}`, 200)
	body, _ := json.Marshal(map[string]any{"id": r.ID, "version": r.Version, "kind": "allow", "process": r.Match.Process, "proto": "tcp", "direction": "out", "port": 80, "ip": "1.2.3.4", "hosts": []string{"h2"}, "bindings": r.Match.Bindings})
	moved := ruleRequest(t, s, string(body), 200)
	if len(moved.Match.Bindings) != 1 || moved.Match.Bindings[0].Host != "h2" {
		t.Fatal(moved.Match.Bindings)
	}
	c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "1.2.3.4", RemotePort: 80, Cgroup: "system.slice/nginx.service"}
	if !bindingHits(t, s, "h2", c) || bindingHits(t, s, "h", c) {
		t.Fatal("service did not move")
	}
}

func TestBindingOutsideScopeRejected(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	w := httptest.NewRecorder()
	body := `{"kind":"allow","process":"app","proto":"tcp","direction":"out","port":80,"ip":"1.2.3.4","hosts":["h2"],"bindings":[{"host":"h","name":"app","cgroup":"system.slice/docker-0123456789ab.scope"}]}`
	s.handlePolicyRule(w, httptest.NewRequest("POST", "/ui/api/rule", bytes.NewBufferString(body)))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "вне выбранных") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOnceConsumedStaysSpentAfterPoll(t *testing.T) {
	s, cert := batchFixture(t)
	r := ruleRequest(t, s, `{"kind":"allow","when":"once","ip":"198.18.0.9","proto":"tcp","port":80,"hosts":["h"]}`, 200)
	if err := s.recordOnceUsed("a", []string{r.ID}); err != nil {
		t.Fatal(err)
	}
	rs, _ := hostRules(s.st.DB, "h")
	if _, ok := policy.Evaluate(rs, "h", policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "198.18.0.9", RemotePort: 80}, store.NowMS()); ok {
		t.Fatal("spent once still matches")
	}
	if err := s.recordOnceUsed("a", []string{r.ID}); err != nil {
		t.Fatal(err)
	}
	_ = cert
}

func TestOnceSkipsSessionCgroup(t *testing.T) {
	s, _ := batchFixture(t)
	body := `{"kind":"allow","when":"once","ip":"198.18.9.9","proto":"tcp","port":80,"hosts":["h"],"process":"nc","bindings":[{"host":"h","name":"nc","cgroup":"user.slice/user-1001.slice/session-286.scope"}]}`
	r := ruleRequest(t, s, body, 200)
	if r.Once != true {
		t.Fatal("once")
	}
	if len(r.Match.Bindings) != 0 {
		t.Fatalf("bindings kept %#v", r.Match.Bindings)
	}
	if r.Match.Process != "" {
		t.Fatalf("process %q", r.Match.Process)
	}
}

func TestOnceRuleDeletedAfterSpend(t *testing.T) {
	s, _ := batchFixture(t)
	r := ruleRequest(t, s, `{"kind":"allow","when":"once","ip":"198.18.0.9","proto":"tcp","port":80,"hosts":["h"]}`, 200)
	if err := s.recordOnceUsed("a", []string{r.ID}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM policy_rules WHERE rule_id=?`, r.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("once rule still stored n=%d err=%v", n, err)
	}
}

func TestRuleDNSNameStored(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(string) ([]netip.Addr, error) { return nil, nil }
	t.Cleanup(func() { lookupNameIPs = prev })
	s, _ := batchFixture(t)
	r := ruleRequest(t, s, `{"kind":"allow","addr":"security.ubuntu.com","proto":"tcp","port":443,"hosts":["h"]}`, 200)
	if len(r.Match.Names) != 1 || r.Match.Names[0] != "security.ubuntu.com" {
		t.Fatalf("names %#v", r.Match.Names)
	}
	if len(r.Match.Networks) != 0 {
		t.Fatalf("networks %#v", r.Match.Networks)
	}
}

func TestStarterTogglesDefaultRules(t *testing.T) {
	s, _ := batchFixture(t)
	if err := s.st.Update(seedPolicy); err != nil {
		t.Fatal(err)
	}
	st := starterState(s.st.DB)
	if !st["ssh"] || !st["dns"] || !st["monitor"] {
		t.Fatal(st)
	}
	w := httptest.NewRecorder()
	s.handleSaveSettings(w, httptest.NewRequest("POST", "/ui/api/settings", bytes.NewBufferString(`{"starter":{"ssh":false,"dns":true,"ntp":true,"ubuntu":true,"monitor":true}}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	rs, _ := readPolicyRules(s.st.DB)
	for _, r := range rs {
		if r.ID == "default-ssh" && r.Enabled {
			t.Fatal("ssh starter still on")
		}
		if r.ID == "default-dns-udp" && !r.Enabled {
			t.Fatal("dns starter off")
		}
	}
	w = httptest.NewRecorder()
	s.handleSaveSettings(w, httptest.NewRequest("POST", "/ui/api/settings", bytes.NewBufferString(`{"starter":{"monitor":false}}`)))
	if w.Code == 200 {
		t.Fatal("monitor protection dropped")
	}
}

func TestEditorMatrixKeepsFieldsVersionAndDeny(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	r := ruleRequest(t, s, `{"name":"web","kind":"allow","ip":"198.18.7.1","proto":"tcp","direction":"out","port":443,"hosts":["h"],"validity":{"mode":"dur","durN":2,"durUnit":"h"}}`, 200)
	if r.ID == "" || r.Version != 1 || r.UntilMS == 0 || r.Match.RemotePort != 443 || r.Action != "allow" {
		t.Fatal(r)
	}
	body, _ := json.Marshal(map[string]any{
		"id": r.ID, "version": r.Version, "name": "web", "kind": "allow", "enabled": false,
		"ip": "198.18.7.1", "proto": "tcp", "direction": "out", "port": 443, "hosts": []string{"h"},
		"from_ms": r.FromMS, "until_ms": r.UntilMS,
	})
	off := ruleRequest(t, s, string(body), 200)
	if off.Version != 2 || off.Enabled || off.UntilMS != r.UntilMS {
		t.Fatal(off)
	}
	copyBody, _ := json.Marshal(map[string]any{
		"name": "web (копия)", "kind": "allow", "ip": "198.18.7.1", "proto": "tcp", "direction": "out", "port": 443, "hosts": []string{"h", "h2"},
	})
	dup := ruleRequest(t, s, string(copyBody), 200)
	if dup.ID == r.ID || dup.Version != 1 {
		t.Fatal(dup)
	}
	deny := ruleRequest(t, s, `{"name":"cut","kind":"deny","ip":"198.18.7.8","proto":"tcp","direction":"in","portSide":"local","port":22,"hosts":["h"]}`, 200)
	if deny.Action != "deny" {
		t.Fatal(deny)
	}
	var bans int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks").Scan(&bans)
	if bans != 0 {
		t.Fatal("deny became a ban")
	}
	del, _ := json.Marshal(map[string]any{"id": dup.ID, "version": dup.Version, "op": "delete"})
	ruleRequest(t, s, string(del), 200)
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM policy_rules WHERE rule_id=?", dup.ID).Scan(&n)
	if n != 0 {
		t.Fatal("duplicate remained")
	}
}

func TestDuplicateRuleRejected(t *testing.T) {
	s, _ := batchFixture(t)
	ruleRequest(t, s, `{"name":"one","kind":"allow","ip":"198.18.1.1","proto":"tcp","direction":"out","port":43,"hosts":["h"]}`, 200)
	w := httptest.NewRecorder()
	s.handlePolicyRule(w, httptest.NewRequest("POST", "/ui/api/rule", bytes.NewBufferString(`{"name":"two","kind":"allow","ip":"198.18.1.1","proto":"tcp","direction":"out","port":43,"hosts":["h"]}`)))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "уже есть") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestServiceRuleHandsOff(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec(`INSERT OR REPLACE INTO settings(k,v) VALUES('monitor_host_id','h')`)
	if err := s.ensureMonitorServiceRules(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handlePolicyRule(w, httptest.NewRequest("POST", "/ui/api/rule", bytes.NewBufferString(`{"op":"delete","id":"monitor-svc-whois","version":1}`)))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "руками не трогать") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestQuestionOfflineCatchupAndProcessScope(t *testing.T) {
	s, cert := batchFixture(t)
	sendQ := func(id, path string, seq int64, lp, rp int, dir string) {
		t.Helper()
		p := protocol.QuestionPayload{
			Direction: dir, Protocol: "tcp", RemoteIP: "198.18.9.9", LocalPort: lp, RemotePort: rp,
			DedupKey: dir + "|tcp|198.18.9.9|" + fmt.Sprint(lp) + "|" + fmt.Sprint(rp) + "|" + path, ProcPath: path, ProcComm: "curl", Repeats: 1,
		}
		raw, _ := json.Marshal(p)
		code, ack := sendBatch(t, s, cert, protocol.Event{EventID: id, Seq: seq, Kind: "question", ObservedAtMS: store.NowMS(), Payload: raw})
		if code != 200 || len(ack.Ack) != 1 {
			t.Fatalf("question %s: %d %+v", id, code, ack)
		}
	}
	sendQ("q1", "cgroup=system.slice/nm-p3-curl.service", 1, 0, 80, "out")
	sendQ("q2", "cgroup=system.slice/other.service", 2, 0, 80, "out")
	ruleRequest(t, s, `{"kind":"allow","proto":"tcp","direction":"out","port":80,"ip":"198.18.9.9","hosts":["h"],"together":true,"bindings":[{"host":"h","name":"curl","cgroup":"system.slice/nm-p3-curl.service"}]}`, 200)
	var curl, other string
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE proc_path LIKE '%nm-p3-curl%'").Scan(&curl)
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE proc_path LIKE '%other.service%'").Scan(&other)
	if curl != "answered" || other != "open" {
		t.Fatal("process match expanded", curl, other)
	}
	sendQ("q1b", "cgroup=system.slice/nm-p3-curl.service", 3, 0, 80, "out")
	var open int
	s.st.DB.QueryRow("SELECT count(*) FROM learn_questions WHERE proc_path LIKE '%nm-p3-curl%' AND status='open'").Scan(&open)
	if open != 0 {
		t.Fatal("covered catch-up reopened", open)
	}
	sendQ("qin", "", 4, 443, 51000, "in")
	ruleRequest(t, s, `{"kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":443,"hosts":["h"]}`, 200)
	var inbound string
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE direction='in'").Scan(&inbound)
	if inbound != "answered" {
		t.Fatal("inbound local port stayed open", inbound)
	}
}

func TestAutobanLadderAndCatchup(t *testing.T) {
	s, cert := batchFixture(t)
	now := store.NowMS()
	scan := func(id string, seq int64, observed int64) {
		t.Helper()
		p := protocol.ScanPayload{IP: "203.0.113.40", Ports: []int{22, 80, 443, 3306, 8080}}
		for _, port := range p.Ports {
			p.Attempts = append(p.Attempts, protocol.ScanAttempt{Protocol: "tcp", Port: port})
		}
		raw, _ := json.Marshal(p)
		code, _ := sendBatch(t, s, cert, protocol.Event{EventID: id, Seq: seq, Kind: "scan", ObservedAtMS: observed, Payload: raw})
		if code != 200 {
			t.Fatal(code)
		}
	}
	scan("s1", 1, now)
	var step int
	var exp int64
	s.st.DB.QueryRow("SELECT escalate_step, expires_at_ms FROM blocks WHERE remote_ip='203.0.113.40' AND state='active'").Scan(&step, &exp)
	if step != 0 || exp-now < time.Hour.Milliseconds()/2 {
		t.Fatal(step, exp-now)
	}
	s.st.DB.Exec("UPDATE blocks SET state='expired', expires_at_ms=?", now-1)
	scan("s2", 2, now)
	s.st.DB.QueryRow("SELECT escalate_step, expires_at_ms FROM blocks WHERE remote_ip='203.0.113.40' AND state='active'").Scan(&step, &exp)
	if step != 1 || exp-now < 5*time.Hour.Milliseconds() {
		t.Fatal("ladder", step, exp-now)
	}
	var persist int
	s.st.DB.QueryRow("SELECT CASE WHEN escalate_step>0 THEN 1 ELSE 0 END FROM blocks WHERE remote_ip='203.0.113.40' AND state='active'").Scan(&persist)
	if persist != 1 {
		t.Fatal("persist")
	}
	late := protocol.ScanPayload{IP: "203.0.113.41", Ports: []int{22, 80, 443, 3306, 8080}}
	for _, port := range late.Ports {
		late.Attempts = append(late.Attempts, protocol.ScanAttempt{Protocol: "tcp", Port: port})
	}
	raw, _ := json.Marshal(late)
	body, _ := json.Marshal(protocol.Batch{Lane: "history", Events: []protocol.Event{{EventID: "old", Seq: 3, Kind: "scan", ObservedAtMS: now, Payload: raw}}})
	req := httptest.NewRequest("POST", "/v1/batch", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, req)
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE remote_ip='203.0.113.41'").Scan(&n)
	if n != 0 {
		t.Fatal("history lane banned")
	}
	stale := protocol.ScanPayload{IP: "203.0.113.42", Ports: []int{22, 80, 443, 3306, 8080}}
	for _, port := range stale.Ports {
		stale.Attempts = append(stale.Attempts, protocol.ScanAttempt{Protocol: "tcp", Port: port})
	}
	raw, _ = json.Marshal(stale)
	sendBatch(t, s, cert, protocol.Event{EventID: "stale", Seq: 4, Kind: "scan", ObservedAtMS: now - 120_000, Payload: raw})
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE remote_ip='203.0.113.42'").Scan(&n)
	if n != 0 {
		t.Fatal("late event banned")
	}
	manual := protocol.ScanPayload{IP: "203.0.113.43", Ports: []int{22, 80, 443, 3306, 8080}}
	for _, port := range manual.Ports {
		manual.Attempts = append(manual.Attempts, protocol.ScanAttempt{Protocol: "tcp", Port: port})
	}
	raw, _ = json.Marshal(manual)
	sendBatch(t, s, cert, protocol.Event{EventID: "m1", Seq: 5, Kind: "scan", ObservedAtMS: now, Payload: raw})
	var mid string
	s.st.DB.QueryRow("SELECT block_id FROM blocks WHERE remote_ip='203.0.113.43' AND state='active'").Scan(&mid)
	if mid == "" {
		t.Fatal("manual setup")
	}
	if _, err := s.st.DB.Exec("UPDATE blocks SET state='removed', removed_at_ms=? WHERE block_id=?", now, mid); err != nil {
		t.Fatal(err)
	}
	sendBatch(t, s, cert, protocol.Event{EventID: "m2", Seq: 6, Kind: "scan", ObservedAtMS: now, Payload: raw})
	s.st.DB.QueryRow("SELECT escalate_step FROM blocks WHERE remote_ip='203.0.113.43' AND state='active'").Scan(&step)
	if step != 0 {
		t.Fatal("manual unban raised ladder", step)
	}
}

func TestPTRNotUsedForGroupPolicy(t *testing.T) {
	s, cert := batchFixture(t)
	groupReq(t, s, `{"name":"names","policy":"allow","members":"*.example.com","hosts":["h"]}`, 200)
	ptr, _ := json.Marshal(protocol.DNSPayload{Name: "www.example.com", IP: "203.0.113.9", Kind: "ptr"})
	sendBatch(t, s, cert, protocol.Event{EventID: "ptr", Seq: 1, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: ptr})
	gs, _ := hostGroups(s.st.DB, "h")
	if _, ok := policy.Evaluate(gs, "h", policy.Contact{RemoteIP: "203.0.113.9", Host: "h"}, store.NowMS()); ok {
		t.Fatal("PTR became policy")
	}
	fwd, _ := json.Marshal(protocol.DNSPayload{Name: "www.example.com", IP: "203.0.113.9", Kind: "a"})
	sendBatch(t, s, cert, protocol.Event{EventID: "a", Seq: 2, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: fwd})
	gs, _ = hostGroups(s.st.DB, "h")
	if _, ok := policy.Evaluate(gs, "h", policy.Contact{RemoteIP: "203.0.113.9", Host: "h"}, store.NowMS()); !ok {
		t.Fatal("forward DNS ignored")
	}
}

func TestWildcardDoesNotMatchNeighbor(t *testing.T) {
	if patternMatches("notubuntu.com", "*.ubuntu.com") {
		t.Fatal("suffix")
	}
	if !patternMatches("security.ubuntu.com", "*.ubuntu.com") {
		t.Fatal("subdomain")
	}
}

func TestURLAndFileGroupImport(t *testing.T) {
	s, _ := batchFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.70\n# comment\n198.51.100.8/32\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "members.txt")
	if err := os.WriteFile(path, []byte("203.0.113.71\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := groupReq(t, s, `{"name":"import","policy":"block","members":`+mustJSON(srv.URL+"\n"+path)+`,"hosts":["h"]}`, 200)
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM ip_group_members WHERE group_id=? AND source IN ('url','file')", id).Scan(&n)
	if n != 3 {
		t.Fatal("imported", n)
	}
}

// Потолка нет: при шквале адрес всё равно банится, а сервер уходит в шторм.
func TestAutobanStormKeepsBanning(t *testing.T) {
	s, cert := batchFixture(t)
	now := store.NowMS()
	for i := 0; i < 20; i++ {
		if _, err := s.st.DB.Exec(
			`INSERT INTO blocks(block_id,scope_kind,host_id,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms)
			 VALUES(?,'host','h',?,zeroblob(16),'both','active','перебор SSH','ssh','auto',?)`,
			fmt.Sprintf("cap-%d", i), fmt.Sprintf("198.51.100.%d", i+1), now,
		); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.80", User: "nobody", Note: "Failed password"})
	for seq := int64(1); seq <= 6; seq++ {
		sendBatch(t, s, cert, protocol.Event{EventID: fmt.Sprintf("cap-ssh-%d", seq), Seq: seq, Kind: "ssh", ObservedAtMS: now, Payload: raw})
	}
	var bans, alerts, capAlerts int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE remote_ip='203.0.113.80' AND state='active'").Scan(&bans)
	s.st.DB.QueryRow("SELECT count(*) FROM alerts WHERE rule_id='storm' AND closed_at_ms IS NULL").Scan(&alerts)
	s.st.DB.QueryRow("SELECT count(*) FROM alerts WHERE rule_id IN ('ssh-cap','scan-cap')").Scan(&capAlerts)
	if bans != 1 || alerts != 1 || capAlerts != 0 {
		t.Fatal("storm", bans, alerts, capAlerts)
	}
	if !stormActive(s.st.DB, "h", store.NowMS()) {
		t.Fatal("storm not active")
	}
	if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('park_mode','allow') ON CONFLICT(k) DO UPDATE SET v='allow'`); err != nil {
		t.Fatal(err)
	}
	var res protocol.PollRes
	if err := s.st.Update(func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRow(`SELECT agent_id FROM agents WHERE host_id='h' AND trust_state='trusted'`).Scan(&id); err != nil {
			return err
		}
		var err error
		res, err = s.pollSnapshotTx(tx, id, "trusted", 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res.Mode != "shield" {
		t.Fatal("storm mode", res.Mode)
	}
	if err := s.expireStorms(store.NowMS() + stormHold + 1); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow("SELECT count(*) FROM alerts WHERE rule_id='storm' AND closed_at_ms IS NULL").Scan(&alerts)
	if alerts != 0 || stormActive(s.st.DB, "h", store.NowMS()) {
		t.Fatal("storm did not end", alerts)
	}
}

func TestSSHIndependentHosts(t *testing.T) {
	s, cert := batchFixture(t)
	cert2 := &x509.Certificate{Raw: []byte("second-client-certificate")}
	if _, err := s.st.DB.Exec(`INSERT INTO hosts(host_id) VALUES('h2')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a2','h2',?,'trusted',1)`, tlsutil.Fingerprint(cert2.Raw)); err != nil {
		t.Fatal(err)
	}
	sendSSH := func(cert *x509.Certificate, id string, seq int64) {
		t.Helper()
		raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: "203.0.113.90", User: "nobody", Note: "Failed password"})
		sendBatch(t, s, cert, protocol.Event{EventID: id, Seq: seq, Kind: "ssh", ObservedAtMS: store.NowMS(), Payload: raw})
	}
	for seq := int64(1); seq <= 5; seq++ {
		sendSSH(cert, fmt.Sprintf("h-ssh-%d", seq), seq)
	}
	var n int
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE source='ssh' AND host_id='h' AND state='active'").Scan(&n)
	if n != 1 {
		t.Fatal("first host", n)
	}
	for seq := int64(1); seq <= 5; seq++ {
		sendSSH(cert2, fmt.Sprintf("h2-ssh-%d", seq), seq)
	}
	s.st.DB.QueryRow("SELECT count(*) FROM blocks WHERE source='ssh' AND host_id='h2' AND state='active'").Scan(&n)
	if n != 1 {
		t.Fatal("second host", n)
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestCalendarRangeUsesInclusiveLocalDay(t *testing.T) {
	s, _ := batchFixture(t)
	r := ruleRequest(t, s, `{"kind":"allow","ip":"198.18.0.2","proto":"tcp","port":80,"hosts":["h"],"validity":{"mode":"range","from":"2026-09-22","to":"2026-09-22"}}`, 200)
	if r.FromMS == 0 || r.UntilMS <= r.FromMS {
		t.Fatal(r)
	}
	start := time.UnixMilli(r.FromMS).In(time.Local)
	if start.Hour() != 0 || start.Minute() != 0 {
		t.Fatal("from is not local midnight", start)
	}
	if r.UntilMS != start.AddDate(0, 0, 1).UnixMilli() {
		t.Fatal(r.UntilMS, start)
	}
}
