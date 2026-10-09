package server

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func TestDropFeedKeepsRareHost(t *testing.T) {
	s, cert := batchFixture(t)
	rareCert := &x509.Certificate{Raw: []byte("rare-drop-client")}
	insertHostAgent(t, s, "rare", "ar", "trusted", rareCert)
	base := store.NowMS()
	noisy := make([]protocol.Event, 201)
	for i := 0; i < len(noisy); i++ {
		noisy[i] = fwSpec(t, fmt.Sprintf("noisy-%03d", i), int64(i+1), base+int64(i), "203.0.113.9", "шум", "", 1, "")
	}
	code, ack := sendBatch(t, s, cert, noisy...)
	if code != 200 || len(ack.Ack) != 201 {
		t.Fatalf("noisy %d held %d err %s", code, len(ack.Ack), ack.Error)
	}
	rare := fwSpec(t, "rare-1", 1, base-1, "198.51.100.20", "редкий", "", 1, "")
	code, ack = sendBatch(t, s, rareCert, rare)
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatalf("rare %d %+v", code, ack)
	}
	if !feedHas(t, s, "rare", "rare-1") {
		t.Fatal("filter lost the rare host before flush")
	}
	if feedHas(t, s, "", "rare-1") || feedHas(t, s, "", "noisy-000") {
		t.Fatal("unfiltered feed kept a row past the limit")
	}

	if dropKept(s) != 201 || dropHas(s, "noisy-000") || !dropHas(s, "rare-1") || !dropHas(s, "noisy-200") {
		t.Fatal("cap", dropKept(s), dropHas(s, "noisy-000"), dropHas(s, "rare-1"))
	}
	if !feedHas(t, s, "rare", "rare-1") {
		t.Fatal("flush dropped the rare host")
	}
	all := dropFeed(t, s, "")
	if len(all) != 200 || feedHas(t, s, "", "rare-1") || feedHas(t, s, "", "noisy-000") || !feedHas(t, s, "", "noisy-200") {
		t.Fatalf("unfiltered %d", len(all))
	}
}

func TestImmediateFirewallFeedsLog(t *testing.T) {
	s, cert := batchFixture(t)
	ev := fwEvent("imm", 1, 4)
	code, ack := sendBatch(t, s, cert, ev)
	if code != 200 || len(ack.Ack) != 1 || len(ack.Held) != 0 || countTable(t, s, "firewall_events") != 0 {
		t.Fatalf("batch %d %+v disk %d hits %d", code, ack, countTable(t, s, "firewall_events"), 0)
	}
	if blocked(t, s, "") != 4 {
		t.Fatal("tile", blocked(t, s, ""))
	}
	rows := dropFeed(t, s, "")
	if len(rows) != 1 || rows[0].FlowUID != "imm" || rows[0].Tip != "DROP; попыток: 4" || rows[0].Rule != "DROP" || rows[0].Addr != ":80 ← 203.0.113.9" || rows[0].State != "block" {
		t.Fatalf("feed %+v", rows)
	}
	code, ack = sendBatch(t, s, cert, ev)
	if code != 200 || len(ack.Ack) != 1 || blocked(t, s, "") != 4 || len(dropFeed(t, s, "")) != 1 || countTable(t, s, "firewall_events") != 0 {
		t.Fatalf("replay %d %+v tile %d", code, ack, blocked(t, s, ""))
	}
}

func dropDiskHits(t *testing.T, s *Server, id string) int {
	t.Helper()
	var raw string
	if err := s.st.DB.QueryRow(`SELECT v FROM settings WHERE k=?`, "dp:"+id).Scan(&raw); err != nil {
		t.Fatal(id, err)
	}
	var body struct {
		Hits int `json:"n"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	return body.Hits
}

func countDropKeys(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE k >= 'dp:' AND k < 'dp;'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func fwSpec(t *testing.T, id string, seq, at int64, ip, tag, verdict string, hits int, group string) protocol.Event {
	t.Helper()
	if verdict == "" {
		verdict = "drop"
	}
	lp := 80
	raw, err := json.Marshal(protocol.FirewallPayload{
		GroupID: group, IPVersion: 4, Protocol: "tcp", Direction: "in",
		LocalIP: "192.168.10.180", LocalPort: &lp, RemoteIP: ip,
		Verdict: verdict, RuleTag: tag, Hits: hits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Event{EventID: id, Seq: seq, Kind: "firewall", ObservedAtMS: at, Payload: raw}
}

func insertHostAgent(t *testing.T, s *Server, host, agent, trust string, cert *x509.Certificate) {
	t.Helper()
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id) VALUES(?)`, host); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES(?,?,?,?,1)`,
			agent, host, tlsutil.Fingerprint(cert.Raw), trust)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func dropWant() map[string][]string {
	return map[string][]string{
		"203.0.113.70|dev-postgres|группа":  {"203.0.113.70", "dev-postgres", "группа", "21"},
		"203.0.113.9|dev-postgres|скан":     {"203.0.113.9", "dev-postgres", "скан", "4"},
		"203.0.113.9|dev-postgres|обучение": {"203.0.113.9", "dev-postgres", "обучение", "3"},
		"198.51.100.8|dev-postgres|reject":  {"198.51.100.8", "dev-postgres", "reject", "2"},
		"203.0.113.50|dev-postgres|край":    {"203.0.113.50", "dev-postgres", "край", "5"},
		"203.0.113.80|dev-postgres|drop":    {"203.0.113.80", "dev-postgres", "drop", "1"},
		"9.9.9.9|dev-postgres|обучение":     {"9.9.9.9", "dev-postgres", "обучение", "7"},
		"203.0.113.90|h3|чужой":             {"203.0.113.90", "h3", "чужой", "9"},
	}
}

func dropWithout(src map[string][]string, key string) map[string][]string {
	out := map[string][]string{}
	for k, row := range src {
		if k != key {
			out[k] = row
		}
	}
	return out
}

func blocked(t *testing.T, s *Server, host string) int {
	t.Helper()
	st := s.uiState(host, "activity")
	if st.err != nil {
		t.Fatal(st.err)
	}
	return st.Now.Blocked
}

func dropFeed(t *testing.T, s *Server, host string) []uiFlow {
	t.Helper()
	st := s.uiState(host, "log")
	if st.err != nil {
		t.Fatal(st.err)
	}
	var out []uiFlow
	for _, f := range st.History {
		if f.State == "block" {
			out = append(out, f)
		}
	}
	return out
}

func feedHas(t *testing.T, s *Server, host, uid string) bool {
	t.Helper()
	for _, f := range dropFeed(t, s, host) {
		if f.FlowUID == uid {
			return true
		}
	}
	return false
}

func mustBlock(t *testing.T, rows []uiFlow, uid string) uiFlow {
	t.Helper()
	for _, f := range rows {
		if f.FlowUID == uid {
			return f
		}
	}
	t.Fatalf("no %s", uid)
	return uiFlow{}
}

func countIP(t *testing.T, s *Server, ip string) int {
	t.Helper()
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM firewall_events WHERE remote_ip=?`, ip).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func dropKept(s *Server) int {
	s.drops.mu.Lock()
	defer s.drops.mu.Unlock()
	return len(s.drops.rows)
}

func dropHas(s *Server, id string) bool {
	s.drops.mu.Lock()
	defer s.drops.mu.Unlock()
	_, ok := s.drops.rows[id]
	return ok
}
