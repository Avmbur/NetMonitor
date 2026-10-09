package server

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestUntrustedDNSCannotEnterNameRule(t *testing.T) {
	for _, state := range []string{"pending", "quarantined"} {
		t.Run(state, func(t *testing.T) {
			s, cert := batchFixture(t)
			if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state=?`, state); err != nil {
				t.Fatal(err)
			}
			if _, err := s.st.DB.Exec(`INSERT INTO hosts(host_id) VALUES('target')`); err != nil {
				t.Fatal(err)
			}
			prev := lookupNameIPs
			lookupNameIPs = func(string) ([]netip.Addr, error) { return nil, nil }
			t.Cleanup(func() { lookupNameIPs = prev })
			raw, _ := json.Marshal(protocol.DNSPayload{Name: "review.example.test", IP: "203.0.113.88", Kind: "a"})
			code, ack := sendBatch(t, s, cert, protocol.Event{EventID: "untrusted-dns", Seq: 1, Kind: "dns", ObservedAtMS: store.NowMS(), Payload: raw})
			if code != 200 || len(ack.Ack) != 1 {
				t.Fatalf("DNS: %d %+v", code, ack)
			}
			// Later approval must not legitimize DNS observed before approval.
			if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state='trusted'`); err != nil {
				t.Fatal(err)
			}
			ruleRequest(t, s, `{"kind":"allow","addr":"review.example.test","proto":"tcp","direction":"out","port":443,"hosts":["target"]}`, 200)
			if n := countTable(t, s, "dns_seen"); n != 0 {
				t.Fatalf("untrusted DNS persisted: %d", n)
			}
			rs, err := hostRules(s.st.DB, "target")
			if err != nil {
				t.Fatal(err)
			}
			c := policy.Contact{Host: "target", Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.88", RemotePort: 443}
			if _, ok := policy.Evaluate(rs, "target", c, store.NowMS()); ok {
				t.Fatal("untrusted DNS allowed on another host")
			}
		})
	}
}

func TestLiveDNSPromotionRequiresCurrentTrust(t *testing.T) {
	for _, state := range []string{"trusted", "pending", "quarantined", "revoked"} {
		t.Run(state, func(t *testing.T) {
			s, _ := batchFixture(t)
			raw, _ := json.Marshal(protocol.DNSPayload{Name: "cached.example.test", IP: "203.0.113.89", Kind: "a"})
			s.noteLiveDNS("h", protocol.Event{Payload: raw}, store.NowMS())
			if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state=?`, state); err != nil {
				t.Fatal(err)
			}
			if err := s.st.Update(func(tx *sql.Tx) error { return s.rememberLiveNames(tx, []string{"*.example.test"}) }); err != nil {
				t.Fatal(err)
			}
			want := 0
			if state == "trusted" {
				want = 1
			}
			if n := countTable(t, s, "dns_seen"); n != want {
				t.Fatalf("promoted=%d want=%d", n, want)
			}
		})
	}
}
