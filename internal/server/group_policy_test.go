package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func groupReq(t *testing.T, s *Server, body string, want int) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleGroups(w, httptest.NewRequest("POST", "/", bytes.NewBufferString(body)))
	if w.Code != want {
		t.Fatal(w.Code, w.Body.String())
	}
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	id, _ := v["id"].(string)
	return id
}
func TestGroupScopeOrderAndQuestionResolution(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	for _, h := range []string{"h", "h2"} {
		_, err := s.st.DB.Exec("INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,local_port,remote_port,status) VALUES(?,?,?,1,1,1,'out','tcp','203.0.113.8',55000,80,'open')", h, h, h)
		if err != nil {
			t.Fatal(err)
		}
	}
	id := groupReq(t, s, `{"name":"selected","policy":"allow","members":"203.0.113.0/24","hosts":"all","except":["h2"],"order":1}`, 200)
	var a, b string
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE question_id='h'").Scan(&a)
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE question_id='h2'").Scan(&b)
	if a != "answered" || b != "open" {
		t.Fatal(a, b)
	}
	deny := groupReq(t, s, `{"name":"deny","policy":"block","members":"203.0.113.8","hosts":["h"],"order":0}`, 200)
	gs, err := hostGroups(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	c := policy.Contact{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.8", RemotePort: 80}
	d, ok := policy.Evaluate(gs, "h", c, store.NowMS())
	if !ok || d.Action != "deny" {
		t.Fatal(d)
	}
	raw, _ := json.Marshal(map[string]any{"op": "order", "ids": []string{id, deny}})
	groupReq(t, s, string(raw), 200)
	gs, _ = hostGroups(s.st.DB, "h")
	d, _ = policy.Evaluate(gs, "h", c, store.NowMS())
	if d.Action != "allow" {
		t.Fatal(d)
	}
	groupReq(t, s, `{"op":"order","ids":[]}`, 400)
	// A rule joining an address and a group can never widen to all group members.
	raw, _ = json.Marshal(map[string]any{"addr": "203.0.113.7", "group": id, "hosts": []string{"h"}, "kind": "allow"})
	r := ruleRequest(t, s, string(raw), 200)
	rs, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rs {
		if rule.ID == r.ID && (len(rule.Match.Networks) != 1 || rule.Match.Networks[0] != "203.0.113.7/32") {
			t.Fatal(rule)
		}
	}
	raw, _ = json.Marshal(map[string]any{"op": "delete", "id": id})
	groupReq(t, s, string(raw), 400)
}

func TestGroupPatternTravelsAsName(t *testing.T) {
	s, _ := batchFixture(t)
	id := groupReq(t, s, `{"name":"ubuntu","policy":"watch","members":"motd.ubuntu.com","hosts":"all"}`, 200)
	gs, err := hostGroups(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, g := range gs {
		if g.ID != id {
			continue
		}
		found = len(g.Match.Names) == 1 && g.Match.Names[0] == "motd.ubuntu.com"
	}
	if !found {
		t.Fatalf("group name was not sent to the agent: %+v", gs)
	}
}

func TestAddMemberKeepsGroupAndMuteLeavesAction(t *testing.T) {
	s, _ := batchFixture(t)
	id := groupReq(t, s, `{"name":"net","policy":"block","members":"203.0.113.1","hosts":["h"],"mute":true}`, 200)
	raw, _ := json.Marshal(map[string]any{"op": "member", "id": id, "members": "203.0.113.8"})
	groupReq(t, s, string(raw), 200)
	var n, mute int
	s.st.DB.QueryRow("SELECT count(*) FROM ip_group_members WHERE group_id=?", id).Scan(&n)
	if n != 2 {
		t.Fatal("add-to-group replaced members", n)
	}
	s.st.DB.QueryRow("SELECT mute_alerts FROM ip_groups WHERE group_id=?", id).Scan(&mute)
	if mute != 1 {
		t.Fatal("mute dropped")
	}
	gs, err := hostGroups(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	d, ok := policy.Evaluate(gs, "h", policy.Contact{RemoteIP: "203.0.113.8", Host: "h"}, store.NowMS())
	if !ok || d.Action != "deny" {
		t.Fatal("mute changed the network action", d, ok)
	}
	raw, _ = json.Marshal(map[string]any{"op": "delete", "id": id})
	groupReq(t, s, string(raw), 200)
	s.st.DB.QueryRow("SELECT count(*) FROM ip_groups WHERE group_id=?", id).Scan(&n)
	if n != 0 {
		t.Fatal("group remained")
	}
}

func TestGroupPatternsResolveTogether(t *testing.T) {
	s, _ := batchFixture(t)
	id := groupReq(t, s, `{"name":"ubuntu","policy":"allow","members":"motd.ubuntu.com\n*.ubuntu.com","hosts":["h"]}`, 200)
	add := func(host, name, ip string) {
		t.Helper()
		a := netip.MustParseAddr(ip)
		if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES(?,?,?,?,1,1)`,
			host, name, netipx.Bin16(a), netipx.Canonical(a)); err != nil {
			t.Fatal(err)
		}
	}
	add("h", "motd.ubuntu.com", "203.0.113.1")
	add("other", "motd.ubuntu.com", "203.0.113.1")
	add("h", "security.ubuntu.com", "203.0.113.2")
	add("h", "ubuntu.com", "203.0.113.3")
	add("h", "notubuntu.com", "203.0.113.4")
	add("h", "example.org", "203.0.113.5")
	gs, err := hostGroups(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	var nets []string
	for _, g := range gs {
		if g.ID == id {
			nets = g.Match.Networks
		}
	}
	joined := strings.Join(nets, ",")
	for _, want := range []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"} {
		if !strings.Contains(joined, want) {
			t.Fatal(nets)
		}
	}
	for _, bad := range []string{"203.0.113.4/32", "203.0.113.5/32"} {
		if strings.Contains(joined, bad) {
			t.Fatal(nets)
		}
	}
	if strings.Count(joined, "203.0.113.1/32") != 2 {
		t.Fatal("same address from two hosts", nets)
	}
}

func TestAlertGroupKeepsQuestionAndBlockCloses(t *testing.T) {
	s, cert := batchFixture(t)
	alertID := groupReq(t, s, `{"name":"сигнал","policy":"alert","members":"198.18.20.1","hosts":["h"]}`, 200)
	raw, _ := json.Marshal(protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "198.18.20.1", RemotePort: 443, DedupKey: "out|tcp|198.18.20.1|443", Repeats: 1})
	code, ack := sendBatch(t, s, cert, protocol.Event{EventID: "qa", Seq: 1, Kind: "question", ObservedAtMS: store.NowMS(), Payload: raw})
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatal(code, ack)
	}
	var st string
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE question_id IN (SELECT question_id FROM learn_questions WHERE remote_ip='198.18.20.1')").Scan(&st)
	if st != "open" {
		t.Fatal("alert closed the question", st)
	}
	groupReq(t, s, `{"id":"`+alertID+`","name":"сигнал","policy":"block","members":"198.18.20.1","hosts":["h"]}`, 200)
	s.st.DB.QueryRow("SELECT status FROM learn_questions WHERE remote_ip='198.18.20.1'").Scan(&st)
	if st != "answered" {
		t.Fatal("block left the question", st)
	}
}
