package server

import (
	"database/sql"
	"encoding/json"
	"testing"

	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func serviceFixture(t *testing.T) (*Server, func(...protocol.Event) (int, protocol.Ack)) {
	t.Helper()
	s, cert := batchFixture(t)

	s.session = "sess-1"
	return s, func(ev ...protocol.Event) (int, protocol.Ack) { return sendBatch(t, s, cert, ev...) }
}

func healthEv(id string, seq int64, p protocol.HealthPayload) protocol.Event {
	raw, _ := json.Marshal(p)
	return protocol.Event{EventID: id, Seq: seq, Kind: "health", ObservedAtMS: store.NowMS(), Payload: raw}
}

func intp(v int) *int { return &v }

// Пульс без инвентаря (сбой сбора, восстановление firewall) не стирает порты SSH.
func TestServiceHealthKeepsInventory(t *testing.T) {
	s, send := serviceFixture(t)
	alive := protocol.HealthPayload{Kind: "alive", BootID: "b1", SSHPort: intp(2222), SSHPorts: []int{2222}, Addresses: []string{"192.168.10.180"}}
	if code, _ := send(healthEv("h1", 1, alive)); code != 200 {
		t.Fatalf("alive %d", code)
	}
	if got := hostSSHPorts(s.st.DB, "h"); len(got) != 1 || got[0] != 2222 {
		t.Fatalf("ssh after alive %v", got)
	}
	var rev int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev)
	if code, _ := send(healthEv("h2", 2, protocol.HealthPayload{Kind: "conntrack_gap", Note: "x"})); code != 200 {
		t.Fatalf("gap %d", code)
	}
	if got := hostSSHPorts(s.st.DB, "h"); len(got) != 1 || got[0] != 2222 {
		t.Fatalf("ssh after gap %v", got)
	}
	var rev2 int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev2)
	if rev2 != rev {
		t.Fatalf("policy bumped by gap %d -> %d", rev, rev2)
	}
	if code, _ := send(healthEv("h3", 3, alive)); code != 200 {
		t.Fatalf("alive again %d", code)
	}
	var rev3 int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev3)
	if rev3 != rev {
		t.Fatalf("same alive bumped policy %d -> %d", rev, rev3)
	}
}

// Перезагрузка сервера: новый boot_id доходит до agents, живой экран не теряет соединения.
func TestServiceHealthUpdatesBoot(t *testing.T) {
	s, send := serviceFixture(t)
	if code, _ := send(healthEv("h1", 1, protocol.HealthPayload{Kind: "alive", BootID: "b0"})); code != 200 {
		t.Fatal(code)
	}
	if code, _ := send(healthEv("h2", 2, protocol.HealthPayload{Kind: "alive", BootID: "b1"})); code != 200 {
		t.Fatal(code)
	}
	var boot string
	if err := s.st.DB.QueryRow(`SELECT boot_id FROM agents WHERE agent_id='a'`).Scan(&boot); err != nil || boot != "b1" {
		t.Fatalf("boot %q %v", boot, err)
	}
	if code, _ := send(flowEvent("f1", 3, openFlow("uid-1"))); code != 200 {
		t.Fatal(code)
	}
	n, _, _, err := s.liveActivity("", false, false)
	if err != nil || n != 1 {
		t.Fatalf("live %d %v", n, err)
	}
}

// Восстановление firewall остаётся в журнале действий.
func TestServiceFirewallRestoredAudited(t *testing.T) {
	s, send := serviceFixture(t)
	if code, _ := send(healthEv("h1", 1, protocol.HealthPayload{Kind: "firewall_restored", Note: "x"})); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "audit_log"); n != 1 {
		t.Fatalf("audit %d", n)
	}
}

// Каждая новая пара попадает в dns_seen один раз; политику двигает только имя из группы.
func TestServiceDNSFeedsPolicyNames(t *testing.T) {
	s, send := serviceFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO ip_groups(group_id,name,created_at_ms) VALUES('g','gh',1)`); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO ip_group_patterns(group_id,pattern) VALUES('g','*.github.com')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var rev int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev)
	dns := func(id string, seq int64, name, ip string) protocol.Event {
		raw, _ := json.Marshal(protocol.DNSPayload{Name: name, IP: ip, Kind: "a"})
		return protocol.Event{EventID: id, Seq: seq, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: raw}
	}
	if code, _ := send(dns("d1", 1, "api.github.com", "140.82.112.6"), dns("d2", 2, "example.org", "93.184.216.34")); code != 200 {
		t.Fatal(code)
	}
	if n := countTable(t, s, "dns_seen"); n != 2 {
		t.Fatalf("dns_seen %d", n)
	}
	var rev2 int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev2)
	if rev2 == rev {
		t.Fatal("policy not refreshed")
	}
	if code, _ := send(dns("d3", 3, "api.github.com", "140.82.112.6")); code != 200 {
		t.Fatal(code)
	}
	var rev3 int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev3)
	if rev3 != rev2 {
		t.Fatal("repeat pair bumped policy")
	}
	if code, _ := send(dns("d4", 4, "other.example.org", "93.184.216.35")); code != 200 {
		t.Fatal(code)
	}
	var rev4 int
	_ = s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id='a'`).Scan(&rev4)
	if rev4 != rev2 || countTable(t, s, "dns_seen") != 3 {
		t.Fatal("name outside policy bumped policy or was not stored", rev4, rev2)
	}
}

// Вопрос, который уже покрыт правилом, сразу закрывается.
func TestServiceQuestionCoveredByRule(t *testing.T) {
	s, send := serviceFixture(t)
	r := policy.Rule{ID: "r1", Version: 1, Enabled: true, Action: "allow", Name: "https",
		Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 443}}
	raw, _ := json.Marshal(r)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('r1',1,1,?)`, string(raw))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	q, _ := json.Marshal(protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, DedupKey: "q"})
	if code, _ := send(protocol.Event{EventID: "q1", Seq: 1, Kind: "question", ObservedAtMS: store.NowMS(), Payload: q}); code != 200 {
		t.Fatal(code)
	}
	var open int
	_ = s.st.DB.QueryRow(`SELECT COUNT(*) FROM learn_questions WHERE status='open'`).Scan(&open)
	if open != 0 {
		t.Fatalf("covered question left open %d", open)
	}
}

// Сеанс памяти не поднимает старый снимок open_flows: он больше не обновляется.
func TestServiceLiveIgnoresDiskSnapshot(t *testing.T) {
	s, _ := serviceFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO open_flows(flow_uid,agent_id,host_id,boot_id,state_seq,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,direction,origin,
			orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,received_at_ms)
			VALUES('ghost','a','h','b1',5,1,1,4,'tcp','out','host','192.168.10.180',zeroblob(16),'1.2.3.4',zeroblob(16),'192.168.10.180',zeroblob(16),'1.2.3.4',zeroblob(16),'internet',1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, _, _, err := s.liveActivity("", false, false)
	if err != nil || n != 0 {
		t.Fatalf("ghost from disk %d %v", n, err)
	}
}

// Удар DROP виден в ленте журнала и без плановой записи.
func TestServiceDropFeed(t *testing.T) {
	s, send := serviceFixture(t)
	if code, _ := send(fwEvent("fw1", 1, 3)); code != 200 {
		t.Fatal(code)
	}
	if v := s.drops.views(); len(v) != 1 || v[0].hits != 3 {
		t.Fatalf("feed %+v", v)
	}
}

// Закрытые uid не копятся бесконечно.
func TestServiceClosedRotates(t *testing.T) {
	s, send := serviceFixture(t)
	p := openFlow("uid-c")
	if code, _ := send(flowEvent("f1", 1, p)); code != 200 {
		t.Fatal(code)
	}
	end := store.NowMS()
	p.EndedAtMS = &end
	if code, _ := send(flowEvent("f2", 2, p)); code != 200 {
		t.Fatal(code)
	}
	s.live.mu.Lock()
	_, closed := s.live.closed[s.closedUIDLocked("a", "uid-c")]
	s.live.rotateClosedLocked(true)
	s.live.rotateClosedLocked(true)
	_, still := s.live.closed[s.closedUIDLocked("a", "uid-c")]
	_, old := s.live.closedOld[s.closedUIDLocked("a", "uid-c")]
	s.live.mu.Unlock()
	if !closed {
		t.Fatal("closure not recorded")
	}
	if still || old {
		t.Fatal("closed uid kept after two rotations")
	}
}
