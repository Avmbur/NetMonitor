package server

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestDNSNameRuleCoversEveryAddress(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(name string) ([]netip.Addr, error) {
		if name != "cdn.example.test" {
			t.Fatalf("lookup %s", name)
		}
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("203.0.113.11"),
			netip.MustParseAddr("127.0.0.1"),
		}, nil
	}
	t.Cleanup(func() { lookupNameIPs = prev })
	s, cert := batchFixture(t)
	insertQ := func(id, ip string) {
		t.Helper()
		if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
			VALUES(?,?,?,1,1,1,'out','tcp',?,443,'open')`, id, "h", id, ip); err != nil {
			t.Fatal(err)
		}
	}
	insertQ("q11", "203.0.113.11")
	insertQ("qother", "198.51.100.20")
	body := `{"kind":"allow","addr":"cdn.example.test","proto":"tcp","direction":"out","port":443,"hosts":["h"]}`
	r := ruleRequest(t, s, body, 200)
	if len(r.Match.Names) != 1 || r.Match.Names[0] != "cdn.example.test" || len(r.Match.Networks) != 0 {
		t.Fatalf("stored %#v", r.Match)
	}
	var raw string
	if err := s.st.DB.QueryRow(`SELECT payload FROM policy_rules WHERE rule_id=?`, r.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored policy.Rule
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Match.Networks) != 0 || len(stored.Match.Names) != 1 {
		t.Fatalf("payload %#v", stored.Match)
	}
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var nets []string
	for _, rule := range rs {
		if rule.ID == r.ID {
			nets = rule.Match.Networks
		}
	}
	if !strings.Contains(strings.Join(nets, ","), "203.0.113.10/32") || !strings.Contains(strings.Join(nets, ","), "203.0.113.11/32") || strings.Contains(strings.Join(nets, ","), "127.0.0.1") {
		t.Fatal(nets)
	}
	status := func(id string) string {
		t.Helper()
		var st string
		if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id=?`, id).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if status("q11") != "answered" || status("qother") != "open" {
		t.Fatalf("q11=%s other=%s", status("q11"), status("qother"))
	}
	if w := ruleRequest(t, s, body, 400); w.ID != "" {
		t.Fatal("duplicate saved")
	}
	q := protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.12", RemotePort: 443, DedupKey: "later", Repeats: 1}
	qraw, _ := json.Marshal(q)
	draw, _ := json.Marshal(protocol.DNSPayload{Name: "cdn.example.test", IP: "203.0.113.12", Kind: "a"})
	code, ack := sendBatch(t, s, cert,
		protocol.Event{EventID: "qlater", Seq: 1, Kind: "question", ObservedAtMS: store.NowMS(), Payload: qraw},
		protocol.Event{EventID: "dlater", Seq: 2, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: draw},
	)
	if code != 200 || len(ack.Ack) != 2 {
		t.Fatalf("batch %d %+v", code, ack)
	}
	var later string
	if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE remote_ip=?`, "203.0.113.12").Scan(&later); err != nil {
		t.Fatal(err)
	}
	if later != "answered" {
		t.Fatal(later)
	}
	rs, err = hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rs {
		if rule.ID == r.ID && !strings.Contains(strings.Join(rule.Match.Networks, ","), "203.0.113.12/32") {
			t.Fatal(rule.Match.Networks)
		}
	}
}

func TestUnresolvedNameRuleOpensNothing(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(string) ([]netip.Addr, error) { return nil, nil }
	t.Cleanup(func() { lookupNameIPs = prev })
	s, _ := batchFixture(t)
	if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
		VALUES('qany','h','qany',1,1,1,'out','tcp','198.51.100.20',443,'open')`); err != nil {
		t.Fatal(err)
	}
	r := ruleRequest(t, s, `{"kind":"allow","addr":"gone.example.test","proto":"tcp","direction":"out","port":443,"hosts":["h"]}`, 200)
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rs {
		if rule.ID == r.ID && (rule.Match.Networks == nil || len(rule.Match.Networks) != 0) {
			t.Fatalf("unresolved name widened: %#v", rule.Match.Networks)
		}
	}
	if _, ok := policy.Evaluate(rs, "h", policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "198.51.100.20", RemotePort: 443}, store.NowMS()); ok {
		t.Fatal("unresolved name allowed any address")
	}
	var st string
	if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id='qany'`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "open" {
		t.Fatal(st)
	}
}

func TestRepeatedDNSAnswerKeepsPolicyRev(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(string) ([]netip.Addr, error) { return nil, nil }
	t.Cleanup(func() { lookupNameIPs = prev })
	s, cert := batchFixture(t)
	ruleRequest(t, s, `{"kind":"allow","addr":"cdn.example.test","proto":"tcp","direction":"out","port":443,"hosts":["h"]}`, 200)
	rev := func() int64 {
		t.Helper()
		var v int64
		if err := s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE host_id='h'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	seq := int64(0)
	observed := store.NowMS()
	send := func(ip string) {
		t.Helper()
		seq++
		raw, _ := json.Marshal(protocol.DNSPayload{Name: "cdn.example.test", IP: ip, Kind: "a"})
		code, ack := sendBatch(t, s, cert, protocol.Event{EventID: "d" + strings.Repeat("x", int(seq)), Seq: seq, Kind: "dns", ObservedAtMS: observed, Payload: raw})
		if code != 200 || len(ack.Ack) != 1 {
			t.Fatalf("batch %d %+v", code, ack)
		}
	}
	before := rev()
	send("203.0.113.10")
	first := rev()
	if first == before {
		t.Fatal("new address did not bump policy")
	}
	send("203.0.113.10")
	send("203.0.113.10")
	if rev() != first {
		t.Fatalf("repeated answer bumped policy: %d -> %d", first, rev())
	}
	// Reordered observations must also leave the revision alone.
	observed--
	send("203.0.113.10")
	if rev() != first {
		t.Fatal("older duplicate bumped policy")
	}
	send("203.0.113.11")
	if rev() != first+1 {
		t.Fatalf("second address: rev=%d want=%d", rev(), first+1)
	}
	// A pair already known on another host is not globally new.
	otherIP := netip.MustParseAddr("203.0.113.12")
	if _, err := s.st.DB.Exec("INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES(?,?,?,?,?,?)",
		"other", "cdn.example.test", netipx.Bin16(otherIP), otherIP.String(), observed, observed); err != nil {
		t.Fatal(err)
	}
	send(otherIP.String())
	if rev() != first+1 {
		t.Fatal("pair from another host bumped policy")
	}
	// Two new envelopes for the same pair inside one batch bump only once.
	raw, _ := json.Marshal(protocol.DNSPayload{Name: "CDN.EXAMPLE.TEST.", IP: "203.0.113.13", Kind: "a"})
	code, ack := sendBatch(t, s, cert,
		protocol.Event{EventID: "same-time-a", Seq: seq + 1, Kind: "dns", ObservedAtMS: observed, Payload: raw},
		protocol.Event{EventID: "same-time-b", Seq: seq + 2, Kind: "dns", ObservedAtMS: observed, Payload: raw})
	if code != 200 || len(ack.Ack) != 2 || rev() != first+2 {
		t.Fatalf("same batch: code=%d ack=%+v rev=%d", code, ack, rev())
	}
}

func TestFreshDNSPairClosesOpenQuestions(t *testing.T) {
	s, cert := batchFixture(t)
	groupReq(t, s, `{"name":"ubuntu","policy":"allow","members":"motd.ubuntu.com\n*.ubuntu.com","hosts":["h"]}`, 200)
	old := netip.MustParseAddr("203.0.113.5")
	if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES(?,?,?,?,?,?)`,
		"h", "motd.ubuntu.com", netipx.Bin16(old), netipx.Canonical(old), 1, 1); err != nil {
		t.Fatal(err)
	}
	insert := func(id, ip string) {
		t.Helper()
		if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
			VALUES(?,?,?,1,1,1,'out','tcp',?,443,'open')`, id, "h", id, ip); err != nil {
			t.Fatal(err)
		}
	}
	insert("q-old", old.String())
	insert("q-new", "203.0.113.6")
	insert("q-other", "198.51.100.9")
	rev := func() int64 {
		t.Helper()
		var v int64
		if err := s.st.DB.QueryRow(`SELECT policy_rev FROM agents WHERE host_id='h'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	status := func(id string) string {
		t.Helper()
		var st string
		if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id=?`, id).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	before := rev()
	dnsEv := func(id string, seq int64, name, ip string) protocol.Event {
		raw, _ := json.Marshal(protocol.DNSPayload{Name: name, IP: ip, Kind: "a"})
		return protocol.Event{EventID: id, Seq: seq, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: raw}
	}
	code, ack := sendBatch(t, s, cert,
		dnsEv("again", 1, "motd.ubuntu.com", old.String()),
		dnsEv("foreign", 2, "example.org", "203.0.113.8"))
	if code != 200 || len(ack.Ack) != 2 || rev() != before {
		t.Fatalf("repeat batch code=%d ack=%+v rev=%d before=%d", code, ack, rev(), before)
	}
	if status("q-old") != "open" || status("q-new") != "open" || status("q-other") != "open" {
		t.Fatalf("repeat closed %s %s %s", status("q-old"), status("q-new"), status("q-other"))
	}
	code, ack = sendBatch(t, s, cert,
		dnsEv("again2", 3, "motd.ubuntu.com", old.String()),
		dnsEv("foreign2", 4, "example.org", "203.0.113.8"),
		dnsEv("fresh", 5, "motd.ubuntu.com", "203.0.113.6"))
	if code != 200 || len(ack.Ack) != 3 || rev() != before+1 {
		t.Fatalf("fresh batch code=%d ack=%+v rev=%d", code, ack, rev())
	}
	if status("q-old") != "answered" || status("q-new") != "answered" || status("q-other") != "open" {
		t.Fatalf("fresh %s %s %s", status("q-old"), status("q-new"), status("q-other"))
	}
}

// Пара в dns_seen общая: второй сервер её уже не пришлёт, его вопрос закрывает первый.
func TestFreshDNSPairClosesOtherHostQuestions(t *testing.T) {
	s, cert := batchFixture(t)
	if _, err := s.st.DB.Exec(`INSERT INTO hosts(host_id) VALUES('h2')`); err != nil {
		t.Fatal(err)
	}
	groupReq(t, s, `{"name":"ubuntu","policy":"allow","members":"motd.ubuntu.com","hosts":["h","h2"]}`, 200)
	if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
		VALUES('q2','h2','q2',1,1,1,'out','tcp','203.0.113.6',443,'open')`); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(protocol.DNSPayload{Name: "motd.ubuntu.com", IP: "203.0.113.6", Kind: "a"})
	code, ack := sendBatch(t, s, cert, protocol.Event{EventID: "fresh", Seq: 1, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: raw})
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("batch %d %+v", code, ack)
	}
	var st string
	if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id='q2'`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "answered" {
		t.Fatal("question on the other host stayed open:", st)
	}
}

func TestRuleNamesResolveTogether(t *testing.T) {
	s, _ := batchFixture(t)
	r := policy.Rule{ID: "two", Version: 1, Enabled: true, Action: "allow", Name: "two",
		Match: policy.Match{Names: []string{"alpha.test", "*.beta.test"}}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('two',1,1,?)`, string(raw)); err != nil {
		t.Fatal(err)
	}
	add := func(name, ip string) {
		t.Helper()
		a := netip.MustParseAddr(ip)
		if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES('h',?,?,?,1,1)`,
			name, netipx.Bin16(a), netipx.Canonical(a)); err != nil {
			t.Fatal(err)
		}
	}
	add("alpha.test", "203.0.113.20")
	add("www.beta.test", "203.0.113.21")
	add("beta.test", "203.0.113.22")
	add("notbeta.test", "203.0.113.23")
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var nets []string
	for _, rule := range rs {
		if rule.ID == "two" {
			nets = rule.Match.Networks
		}
	}
	joined := strings.Join(nets, ",")
	for _, want := range []string{"203.0.113.20/32", "203.0.113.21/32", "203.0.113.22/32"} {
		if !strings.Contains(joined, want) {
			t.Fatal(nets)
		}
	}
	if strings.Contains(joined, "203.0.113.23/32") {
		t.Fatal(nets)
	}
}
