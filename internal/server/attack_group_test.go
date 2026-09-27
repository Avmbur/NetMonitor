package server

import (
	"bytes"
	"database/sql"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/store"
)

func attackCIDRs(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.st.DB.Query(`SELECT cidr FROM ip_group_members WHERE group_id=? ORDER BY cidr`, attackGroupID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err = rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestAttackGroupFollowsForeverBans(t *testing.T) {
	s, _ := batchFixture(t)
	forever := banRequest(t, s, `{"ip":"203.0.113.7","forever":true}`, 200)
	banRequest(t, s, `{"ip":"203.0.113.8"}`, 200)
	got := attackCIDRs(t, s)
	if len(got) != 1 || got[0] != "203.0.113.7/32" {
		t.Fatalf("members %v", got)
	}
	var policy, name string
	if err := s.st.DB.QueryRow(`SELECT name, policy FROM ip_groups WHERE group_id=?`, attackGroupID).Scan(&name, &policy); err != nil {
		t.Fatal(err)
	}
	if name != "служебные - адреса атак" || policy != "observe" {
		t.Fatalf("group %s %s", name, policy)
	}
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := writeBan(tx, banSpec{RemoteIP: "198.51.100.9", Source: "scan", Reason: "скан портов", CreatedBy: "auto"}, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		_, err := writeBan(tx, banSpec{RemoteIP: "198.51.100.10", Source: "ssh", Reason: "перебор SSH", CreatedBy: "auto", ExpiresAt: now + 3600000}, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got = attackCIDRs(t, s)
	if len(got) != 2 || got[0] != "198.51.100.9/32" || got[1] != "203.0.113.7/32" {
		t.Fatalf("after scan %v", got)
	}
	unbanRequest(t, s, `{"id":"`+forever+`"}`, 200)
	got = attackCIDRs(t, s)
	if len(got) != 1 || got[0] != "198.51.100.9/32" {
		t.Fatalf("after unban %v", got)
	}
	w := httptest.NewRecorder()
	s.handleGroups(w, httptest.NewRequest("POST", "/ui/api/groups", bytes.NewBufferString(`{"op":"delete","id":"attacks"}`)))
	if w.Code == 200 {
		t.Fatalf("service group deleted: %s", w.Body.String())
	}
}
