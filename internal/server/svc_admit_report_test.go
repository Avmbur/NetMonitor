package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
	"time"
)

func TestRemoteAgentReportsServiceAdmission(t *testing.T) {
	svcAdmitted.Lock()
	prev := svcAdmitted.until
	svcAdmitted.until = map[string]map[netip.Addr]int64{}
	svcAdmitted.Unlock()
	t.Cleanup(func() { svcAdmitted.Lock(); svcAdmitted.until = prev; svcAdmitted.Unlock() })
	s, cert := batchFixture(t)
	if err := s.ensureUpdateRule(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO hosts(host_id) VALUES('other')`); err != nil {
		t.Fatal(err)
	}
	report := func(entries []protocol.ServiceAdmission, want int) {
		t.Helper()
		raw, _ := json.Marshal(protocol.PollReq{Rev: -1, ServiceAdmitted: entries})
		req := httptest.NewRequest("POST", "/v1/poll", bytes.NewReader(raw))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		w := httptest.NewRecorder()
		s.handlePoll(w, req)
		if w.Code != want {
			t.Fatalf("poll: %d %s", w.Code, w.Body.String())
		}
	}
	until := store.NowMS() + time.Hour.Milliseconds()
	entries := []protocol.ServiceAdmission{{IP: "203.0.113.77", UntilMS: until}, {IP: "2001:db8::77", UntilMS: until}}
	report(entries, 200)
	check := func(host, ip, cgroup string, port int, want string) {
		t.Helper()
		d, err := loadHostDecision(s.st.DB, host, nil, "learn")
		if err != nil {
			t.Fatal(err)
		}
		c := policy.Contact{Host: host, Direction: "out", Protocol: "tcp", RemoteIP: ip, RemotePort: port, Cgroup: cgroup}
		if _, action, _ := d.resolve(c, store.NowMS()); action != want {
			t.Fatalf("%+v: %s want %s", c, action, want)
		}
	}
	for _, e := range entries {
		check("h", e.IP, "system.slice/nmagent.service", 443, "allow")
	}
	check("h", "203.0.113.77", "user.slice/curl", 443, "learn")
	check("h", "203.0.113.77", "system.slice/nmagent.service", 80, "learn")
	check("h", "203.0.113.78", "system.slice/nmagent.service", 443, "learn")
	check("other", "203.0.113.77", "system.slice/nmagent.service", 443, "learn")
	// Repeated reports retain expiry, and reconstruct a lost monitor cache.
	report(entries, 200)
	svcAdmitted.Lock()
	got := svcAdmitted.until["h"][netip.MustParseAddr(entries[0].IP)]
	delete(svcAdmitted.until, "h")
	svcAdmitted.Unlock()
	if got != until {
		t.Fatalf("expiry renewed: %d -> %d", until, got)
	}
	report(entries, 200)
	check("h", "203.0.113.77", "system.slice/nmagent.service", 443, "allow")
	if got := admittedFor("h", until); len(got) != 0 {
		t.Fatalf("expired addresses: %v", got)
	}
	report([]protocol.ServiceAdmission{{IP: "203.0.113.77", UntilMS: store.NowMS() - 1}}, 200)
	if len(admittedFor("h", store.NowMS())) != 0 {
		t.Fatal("expired report reactivated admission")
	}
	report([]protocol.ServiceAdmission{{IP: "invalid", UntilMS: until}}, 400)
	report([]protocol.ServiceAdmission{{IP: "203.0.113.77", UntilMS: store.NowMS() + 72*time.Hour.Milliseconds()}}, 400)
	for _, state := range []string{"pending", "quarantined"} {
		if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state=?`, state); err != nil {
			t.Fatal(err)
		}
		report(entries, 200)
		if len(admittedFor("h", store.NowMS())) != 0 {
			t.Fatalf("%s admission accepted", state)
		}
	}
}
