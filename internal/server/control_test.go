package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"netmonitor/internal/policy"
	"netmonitor/internal/store"
	"testing"
)

func controlRequest(t *testing.T, s *Server, body string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
	req.SetPathValue("id", "a")
	w := httptest.NewRecorder()
	s.handleControl(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestControlInheritanceQuarantineAndPause(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec("INSERT INTO settings(k,v) VALUES('park_mode','learn')")
	controlRequest(t, s, `{"op":"mode","mode":"allow"}`)
	p, e := s.pollSnapshot("a", "trusted", 0)
	if e != nil || p.Mode != "allow" {
		t.Fatal(p, e)
	}
	s.st.DB.Exec("UPDATE settings SET v='block' WHERE k='park_mode'")
	p, e = s.pollSnapshot("a", "trusted", 0)
	if e != nil || p.Mode != "allow" {
		t.Fatal(p, e)
	}
	controlRequest(t, s, `{"op":"mode","mode":"park"}`)
	p, e = s.pollSnapshot("a", "trusted", 0)
	if e != nil || p.Mode != "block" {
		t.Fatal(p, e)
	}
	controlRequest(t, s, `{"op":"quarantine","on":true}`)
	p, e = s.pollSnapshot("a", "trusted", 0)
	if e != nil || p.Mode != "quarantine" {
		t.Fatal(p, e)
	}
	controlRequest(t, s, `{"op":"quarantine","on":false}`)
	p, e = s.pollSnapshot("a", "trusted", 0)
	if e != nil || p.Mode != "block" {
		t.Fatal(p, e)
	}
	// Pause prevents new auto bans on this host, including scans on a different host.
	e = s.st.Update(func(tx *sql.Tx) error { return banInTx(tx, "203.0.113.8", "h", true, "scan", "scan", now) })
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]any{"op": "pause", "on": true, "until_ms": now + 60000})
	controlRequest(t, s, string(raw))
	e = s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "203.0.113.9", "h-other", true, "scan", "scan", now)
	})
	if e != nil {
		t.Fatal(e)
	}
	p, e = s.pollSnapshot("a", "trusted", 0)
	if e != nil || len(p.Blocks) != 1 || p.Blocks[0].RemoteIP != "203.0.113.8" {
		t.Fatal(p, e)
	}
	c, e := readControl(s.st.DB, "h")
	if e != nil || !c.paused(now) || c.paused(now+60000) {
		t.Fatal(c, e)
	}
	st := s.uiState("", "settings")
	if st.err != nil || st.Agents[0].HostID != "h" || st.Agents[0].Control.PauseUntil != now+60000 {
		t.Fatal(st.err, st.Agents)
	}
	// «Пока не сниму» — без срока, держится до снятия.
	controlRequest(t, s, `{"op":"pause","on":true,"forever":true}`)
	c, e = readControl(s.st.DB, "h")
	if e != nil || !c.paused(now+365*24*3600*1000) {
		t.Fatal("forever pause", c, e)
	}
	controlRequest(t, s, `{"op":"pause","on":false}`)
	c, e = readControl(s.st.DB, "h")
	if e != nil || c.paused(now) {
		t.Fatal("unpause", c, e)
	}
}
func TestRuleExclusionsAndGroupIntersection(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2')")
	r := ruleRequest(t, s, `{"kind":"allow","addr":"203.0.113.7","hosts":"all","except":["h2"]}`, 200)
	if !r.OnHost("h") || r.OnHost("h2") {
		t.Fatal(r)
	}
	for _, body := range []string{`{"port":12,"proto":"tcp","portSide":"other"}`, `{"validity":{"mode":"dur","durN":0}}`, `{"validity":{"mode":"typo"}}`} {
		ruleRequest(t, s, body, 400)
	}
	out := policy.IntersectNetworks([]string{"203.0.113.7/32"}, []string{"203.0.113.0/24", "198.51.100.0/24"})
	if len(out) != 1 || out[0] != "203.0.113.7/32" {
		t.Fatal(out)
	}
	out = policy.IntersectNetworks([]string{"192.0.2.0/24"}, []string{"203.0.113.0/24"})
	if out == nil || len(out) != 0 {
		t.Fatal("disjoint became any", out)
	}
}
