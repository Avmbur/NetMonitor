package server

import "testing"

func TestLANClassificationIsNotBlanketFirewallAllow(t *testing.T) {
	s, _ := batchFixture(t)
	s.st.DB.Exec("INSERT INTO settings(k,v) VALUES('lan','10.0.0.0/8,fd00::/8') ON CONFLICT(k) DO UPDATE SET v=excluded.v")
	rules, err := hostRules(s.st.DB, "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		for _, p := range r.Match.Networks {
			if p == "10.0.0.0/8" || p == "fd00::/8" {
				t.Fatal("LAN became firewall exemption")
			}
		}
	}
}
