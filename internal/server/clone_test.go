package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func sendBatchFrom(t *testing.T, s *Server, cert *x509.Certificate, src string, events ...protocol.Event) (int, protocol.Ack) {
	t.Helper()
	raw, err := json.Marshal(protocol.Batch{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(raw))
	r.RemoteAddr = src
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	var ack protocol.Ack
	if w.Code == 200 || w.Code == 409 {
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, ack
}

func pollFrom(t *testing.T, s *Server, cert *x509.Certificate, src string, in protocol.PollReq) protocol.PollRes {
	t.Helper()
	raw, _ := json.Marshal(in)
	r := httptest.NewRequest(http.MethodPost, "/v1/poll", bytes.NewReader(raw))
	r.RemoteAddr = src
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handlePoll(w, r)
	var res protocol.PollRes
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	return res
}

func TestCloneQuarantineSeparatesDataAndCommands(t *testing.T) {
	s, cert := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=?`, now)
	code, _ := sendBatchFrom(t, s, cert, "192.0.2.10:1", scanEvent("orig", 1))
	if code != 200 {
		t.Fatal(code)
	}
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, store.NowMS())
	raw, _ := json.Marshal(protocol.HealthPayload{Kind: "alive", BootID: "clone-boot"})
	code, ack := sendBatchFrom(t, s, cert, "198.51.100.20:2", protocol.Event{
		EventID: "clone-h", Seq: 1, Kind: "health", ObservedAtMS: store.NowMS(), Payload: raw,
	})
	if code != 200 || len(ack.Ack) != 1 {
		t.Fatal(code, ack)
	}
	var n, clones int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents WHERE trust_state='quarantined'`).Scan(&clones)
	if n != 2 || clones != 1 {
		t.Fatal("agents", n, "clones", clones)
	}
	var origHost, cloneHost string
	s.st.DB.QueryRow(`SELECT host_id FROM agents WHERE agent_id='a'`).Scan(&origHost)
	s.st.DB.QueryRow(`SELECT host_id FROM agents WHERE trust_state='quarantined'`).Scan(&cloneHost)
	if origHost == cloneHost {
		t.Fatal("mixed host")
	}
	orig := pollFrom(t, s, cert, "192.0.2.10:3", protocol.PollReq{Rev: 0})
	if !orig.Authorized {
		t.Fatal("original lost commands")
	}
	clone := pollFrom(t, s, cert, "198.51.100.20:4", protocol.PollReq{Rev: 0})
	if clone.Authorized || len(clone.Commands) != 0 || len(clone.Blocks) != 0 {
		t.Fatalf("clone received policy: %+v", clone)
	}
	st := s.uiState("", "settings")
	found := false
	for _, a := range st.Agents {
		if a.Trust == "quarantined" {
			found = true
		}
	}
	if !found {
		t.Fatal("clone hidden")
	}
}

func TestSameIPAndReconnectAreNotClones(t *testing.T) {
	s, cert := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=?`, now)
	if code, _ := sendBatchFrom(t, s, cert, "192.0.2.10:1", scanEvent("a1", 1)); code != 200 {
		t.Fatal(code)
	}
	if code, _ := sendBatchFrom(t, s, cert, "192.0.2.10:2", scanEvent("a2", 2)); code != 200 {
		t.Fatal(code)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	if n != 1 {
		t.Fatal("parallel batch cloned", n)
	}
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=1`)
	if code, _ := sendBatchFrom(t, s, cert, "203.0.113.9:9", scanEvent("moved", 3)); code != 200 {
		t.Fatal(code)
	}
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&n)
	if n != 1 {
		t.Fatal("stale move cloned", n)
	}
}

func TestRevokeCloneLeavesOriginal(t *testing.T) {
	s, cert := batchFixture(t)
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=?`, store.NowMS())
	sendBatchFrom(t, s, cert, "192.0.2.10:1", scanEvent("o", 1))
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, store.NowMS())
	sendBatchFrom(t, s, cert, "198.51.100.20:2", scanEvent("c", 1))
	var cloneID string
	s.st.DB.QueryRow(`SELECT agent_id FROM agents WHERE trust_state='quarantined'`).Scan(&cloneID)
	if cloneID == "" {
		t.Fatal("no clone")
	}
	if err := s.changeAgent(cloneID, "revoke", "", ""); err != nil {
		t.Fatal(err)
	}
	orig := pollFrom(t, s, cert, "192.0.2.10:3", protocol.PollReq{Rev: 0})
	if !orig.Authorized {
		t.Fatal("original revoked")
	}
	raw, _ := json.Marshal(protocol.PollReq{Rev: 0})
	r := httptest.NewRequest(http.MethodPost, "/v1/poll", bytes.NewReader(raw))
	r.RemoteAddr = "198.51.100.20:4"
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handlePoll(w, r)
	if w.Code != 401 {
		t.Fatal("revoked clone still served", w.Code, w.Body.String())
	}
}
