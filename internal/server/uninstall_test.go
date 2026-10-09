package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestRemovalCompletionRetryAndAuthorization(t *testing.T) {
	s, cert := batchFixture(t)
	s.hostSeen = map[string]int64{"h": store.NowMS()}
	if _, err := s.st.DB.Exec("UPDATE hosts SET last_seen_ms=?", store.NowMS()); err != nil {
		t.Fatal(err)
	}
	if err := s.changeAgent("a", "remove", "", ""); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.st.DB.QueryRow("SELECT command_id FROM commands WHERE kind='uninstall'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	post := func(cert *x509.Certificate, phase string) int {
		raw, _ := json.Marshal(protocol.UninstallResult{CommandID: id, Phase: phase, Error: map[string]string{"failed": "nft refused deletion"}[phase]})
		req := httptest.NewRequest("POST", "/v1/uninstall-result", strings.NewReader(string(raw)))
		if cert != nil {
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		}
		w := httptest.NewRecorder()
		s.handleUninstallResult(w, req)
		return w.Code
	}
	count := func(want int) {
		t.Helper()
		var n int
		if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM agents").Scan(&n); err != nil || n != want {
			t.Fatal(n, err)
		}
	}
	if code := post(nil, "prepare"); code != 401 {
		t.Fatal(code)
	}
	if code := post(cert, "prepare"); code == 200 {
		t.Fatal("undelivered removal accepted")
	}
	if _, err := s.pollSnapshot("a", "trusted", 0); err != nil {
		t.Fatal(err)
	}
	if code := post(cert, "complete"); code == 200 {
		t.Fatal("completion before prepare accepted")
	}
	foreign := &x509.Certificate{Raw: []byte("another certificate")}
	if code := post(foreign, "prepare"); code == 200 {
		t.Fatal("foreign certificate accepted")
	}
	if code := post(cert, "prepare"); code != 200 {
		t.Fatal(code)
	}
	count(1)
	if code := post(cert, "prepare"); code != 200 {
		t.Fatal("lost prepare response cannot be retried", code)
	}
	if code := post(cert, "failed"); code != 200 {
		t.Fatal(code)
	}
	count(1)
	ui := s.uiState("", "settings")
	if ui.err != nil || ui.Agents[0].Removing != "error" || ui.Agents[0].RemovalError != "nft refused deletion" {
		t.Fatal(ui.err, ui.Agents)
	}
	// Lost completion response: repeat after the row and its commands have gone.
	if code := post(cert, "complete"); code != 200 {
		t.Fatal(code)
	}
	count(0)
	if code := post(cert, "complete"); code != 200 {
		t.Fatal("lost completion response cannot be retried", code)
	}
	if code := post(foreign, "complete"); code == 200 {
		t.Fatal("foreign receipt replay accepted")
	}
	if code := post(cert, "prepare"); code == 200 {
		t.Fatal("receipt authorized another cleanup")
	}
	if code := postPoll(t, s, cert, protocol.PollReq{}); code != 401 {
		t.Fatal("receipt permits normal polls", code)
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='снял агента с сервера'").Scan(&n); err != nil || n != 1 {
		t.Fatal("duplicate completion audit", n, err)
	}
	// Reopening the DB is not needed for retry: the receipt is a stored setting.
	var receipts int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM settings WHERE k=?", "uninstall_done:"+id).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal(receipts, err)
	}
}
