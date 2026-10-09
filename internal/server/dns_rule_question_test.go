package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/ingest"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func questionStatus(t *testing.T, s *Server, id string) string {
	t.Helper()
	var st string
	if err := s.st.DB.QueryRow(`SELECT status FROM learn_questions WHERE question_id=?`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func openQuestion(t *testing.T, s *Server, id, ip string) {
	t.Helper()
	if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
		VALUES(?,?,?,1,1,1,'out','tcp',?,443,'open')`, id, "h", id, ip); err != nil {
		t.Fatal(err)
	}
}

// Правило по имени из вопроса закрывает вопрос, даже если монитор сам
// резолвит имя в другой адрес. Второй вопрос того же имени с другим адресом
// закрывается тем же правилом, повторно создавать его не нужно.
func TestNameRuleClosesQuestionsOfSeenAddresses(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.121.3")}, nil
	}
	t.Cleanup(func() { lookupNameIPs = prev })
	s, _ := batchFixture(t)
	ag := ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}
	for _, ip := range []string{"140.82.121.4", "140.82.121.5"} {
		raw, _ := json.Marshal(protocol.DNSPayload{Name: "github.com", IP: ip})
		ev := protocol.Event{Kind: "dns", Payload: raw, ObservedAtMS: store.NowMS()}
		if err := s.st.Update(func(tx *sql.Tx) error { _, err := noteDNS(tx, ag, ev); return err }); err != nil {
			t.Fatal(err)
		}
	}
	openQuestion(t, s, "q4", "140.82.121.4")
	openQuestion(t, s, "q5", "140.82.121.5")
	body := `{"kind":"allow","addr":"github.com","proto":"tcp","direction":"out","port":443,"hosts":["h"],"question_id":"q4"}`
	ruleRequest(t, s, body, 200)
	if a, b := questionStatus(t, s, "q4"), questionStatus(t, s, "q5"); a != "answered" || b != "answered" {
		t.Fatalf("q4=%s q5=%s", a, b)
	}
}

// Пара, которую монитор видел только в памяти (до правила или до
// обновления), переносится в базу при создании правила.
func TestNameRuleUsesLiveNames(t *testing.T) {
	prev := lookupNameIPs
	lookupNameIPs = func(string) ([]netip.Addr, error) { return nil, nil }
	t.Cleanup(func() { lookupNameIPs = prev })
	s, _ := batchFixture(t)
	raw, _ := json.Marshal(protocol.DNSPayload{Name: "cdn.example.test", IP: "203.0.113.44"})
	s.noteLiveDNS("h", protocol.Event{Kind: "dns", Payload: raw}, store.NowMS())
	openQuestion(t, s, "q", "203.0.113.44")
	ruleRequest(t, s, `{"kind":"allow","addr":"cdn.example.test","proto":"tcp","direction":"out","port":443,"hosts":["h"],"question_id":"q"}`, 200)
	if st := questionStatus(t, s, "q"); st != "answered" {
		t.Fatal(st)
	}
}

// Клик по адресу находит имя и в памяти (без сервера), и в базе.
func TestDNSLookupByClick(t *testing.T) {
	s, _ := batchFixture(t)
	raw, _ := json.Marshal(protocol.DNSPayload{Name: "live.example.test", IP: "203.0.113.7"})
	s.noteLiveDNS("h", protocol.Event{Kind: "dns", Payload: raw}, store.NowMS())
	if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES('h','disk.example.test',zeroblob(16),'203.0.113.8',1,1)`); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{"203.0.113.7": "live.example.test", "203.0.113.8": "disk.example.test"} {
		w := httptest.NewRecorder()
		s.handleDNSLookup(w, httptest.NewRequest(http.MethodGet, "/ui/api/dns?ip="+ip, nil))
		if !strings.Contains(w.Body.String(), `"name":"`+want+`"`) {
			t.Fatalf("%s: %s", ip, w.Body.String())
		}
	}
}

// Адрес, вписанный агентом в служебный набор, монитор считает покрытым
// служебным правилом: соединение службы не горит и вопрос не держит.
func TestAdmittedAddressCoveredOnMonitor(t *testing.T) {
	s, _ := batchFixture(t)
	r := policy.Rule{ID: "park-svc-update", Version: 1, Enabled: true, Action: "allow", Order: 994,
		Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 443, OnDemand: []string{"api.github.com"}}}
	raw, _ := json.Marshal(r)
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES(?,1,994,?)`, r.ID, string(raw)); err != nil {
		t.Fatal(err)
	}
	c := policy.Contact{Host: "h", Direction: "out", Protocol: "tcp", RemoteIP: "140.82.121.6", RemotePort: 443}
	d, err := loadHostDecision(s.st.DB, "h", nil, "learn")
	if err != nil {
		t.Fatal(err)
	}
	if _, action, _ := d.resolve(c, store.NowMS()); action != "learn" {
		t.Fatalf("before admit %s", action)
	}
	noteAdmitted("h", []netip.Addr{netip.MustParseAddr("140.82.121.6")}, time.Hour)
	t.Cleanup(func() { noteAdmitted("h", []netip.Addr{netip.MustParseAddr("140.82.121.6")}, -time.Hour) })
	d, err = loadHostDecision(s.st.DB, "h", nil, "learn")
	if err != nil {
		t.Fatal(err)
	}
	if _, action, _ := d.resolve(c, store.NowMS()); action != "allow" {
		t.Fatalf("after admit %s", action)
	}
	other := c
	other.RemoteIP = "198.51.100.9"
	if _, action, _ := d.resolve(other, store.NowMS()); action != "learn" {
		t.Fatalf("other address %s", action)
	}
}
