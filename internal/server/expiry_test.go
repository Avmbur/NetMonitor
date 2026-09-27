package server

import (
	"fmt"
	"testing"

	"netmonitor/internal/store"
)

func TestExpiryIsDurableAndDoesNotRefreshForever(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	for _, v := range []struct {
		id     string
		expiry any
	}{{"old", now - 1}, {"future", now + 60000}, {"forever", nil}} {
		_, err := s.st.DB.Exec("INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms,expires_at_ms) VALUES(?,'all','198.18.0.2',zeroblob(16),'both','active','test','test','test',?,?)", v.id, now-100, v.expiry)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.expireBlocks(now); err != nil {
		t.Fatal(err)
	}
	var state string
	s.st.DB.QueryRow("SELECT state FROM blocks WHERE block_id='old'").Scan(&state)
	if state != "expired" {
		t.Fatal(state)
	}
	var n int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM blocks WHERE state='active'").Scan(&n)
	if n != 2 {
		t.Fatal(n)
	}
	var rev int
	s.st.DB.QueryRow("SELECT policy_rev FROM agents").Scan(&rev)
	if err := s.expireBlocks(now); err != nil {
		t.Fatal(err)
	}
	var again int
	s.st.DB.QueryRow("SELECT policy_rev FROM agents").Scan(&again)
	if rev != again {
		t.Fatal("expiry replay bumped policy")
	}
	if _, err := s.st.DB.Exec("CREATE TRIGGER fail_expiry BEFORE UPDATE ON blocks BEGIN SELECT RAISE(ABORT,'disk'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.expireBlocks(now + 120000); err == nil {
		t.Fatal("expiry SQL error hidden")
	}
	s.st.DB.QueryRow("SELECT state FROM blocks WHERE block_id='future'").Scan(&state)
	if state != "active" {
		t.Fatal("partial expiry")
	}
}

func TestExpireTimedRules(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	past := fmt.Sprintf(`{"id":"old","name":"tmp","enabled":true,"action":"allow","until_ms":%d}`, now-1000)
	fut := fmt.Sprintf(`{"id":"live","name":"ok","enabled":true,"action":"allow","until_ms":%d}`, now+60000)
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('old',1,1,?)`, past); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('live',1,2,?)`, fut); err != nil {
		t.Fatal(err)
	}
	if err := s.expireRules(now); err != nil {
		t.Fatal(err)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM policy_rules WHERE rule_id='old'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired rule kept")
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM policy_rules WHERE rule_id='live'`).Scan(&n)
	if n != 1 {
		t.Fatal("live rule dropped")
	}
}
