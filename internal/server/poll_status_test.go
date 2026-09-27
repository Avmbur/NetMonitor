package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func pollFixture(t *testing.T) (*Server, *x509.Certificate) {
	s, cert := batchFixture(t)
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE agents SET policy_rev=2"); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms,delivered_at_ms,delivered_rev) VALUES('cmd','a','ban','{}',1,1,1)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s, cert
}
func postPoll(t *testing.T, s *Server, cert *x509.Certificate, in protocol.PollReq) int {
	t.Helper()
	raw, _ := json.Marshal(in)
	r := httptest.NewRequest(http.MethodPost, "/v1/poll", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handlePoll(w, r)
	return w.Code
}
func TestPollRecordsFailureWithoutAckThenRecovery(t *testing.T) {
	s, cert := pollFixture(t)
	rev := int64(1)
	st := &protocol.ApplyStatus{Backend: "nftables", DesiredRev: 2, AppliedRev: &rev, Error: "nft: Operation not permitted", CommandIDs: []string{"cmd"}}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 1, Status: st}); code != 200 {
		t.Fatal(code)
	}
	var ack sql.NullInt64
	var result, message string
	if err := s.st.DB.QueryRow("SELECT acked_at_ms,result,error FROM commands").Scan(&ack, &result, &message); err != nil {
		t.Fatal(err)
	}
	if ack.Valid || result != "error" || message != st.Error {
		t.Fatal("false confirmation")
	}
	ui := s.uiState("", "settings")
	if len(ui.Agents) != 1 || ui.Agents[0].FW == nil || ui.Agents[0].FWBackend != "nftables" || *ui.Agents[0].FW.AppliedRev != 1 {
		t.Fatal("UI lost result")
	}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 1, Ack: []string{"cmd"}, Status: st}); code == 200 {
		t.Fatal("failed apply ACK accepted")
	}
	rev = 2
	st.Error = ""
	in := protocol.PollReq{Rev: 2, Ack: []string{"cmd"}, Status: st}
	if code := postPoll(t, s, cert, in); code != 200 {
		t.Fatal(code)
	}
	var first int64
	s.st.DB.QueryRow("SELECT acked_at_ms FROM commands").Scan(&first)
	if first == 0 {
		t.Fatal("successful application unconfirmed")
	}
	if code := postPoll(t, s, cert, in); code != 200 {
		t.Fatal("duplicate", code)
	}
	var again int64
	s.st.DB.QueryRow("SELECT acked_at_ms FROM commands").Scan(&again)
	if again != first {
		t.Fatal("replay rewrote ACK")
	}
}
func TestReceiptOnlyAckAndFailedDBNeverSuccess(t *testing.T) {
	s, cert := pollFixture(t)
	if code := postPoll(t, s, cert, protocol.PollReq{Ack: []string{"cmd"}}); code == 200 {
		t.Fatal("receipt-only ACK accepted")
	}
	rev := int64(2)
	in := protocol.PollReq{Rev: 2, Ack: []string{"cmd"}, Status: &protocol.ApplyStatus{Backend: "nftables", DesiredRev: 2, AppliedRev: &rev, CommandIDs: []string{"cmd"}}}
	if _, err := s.st.DB.Exec("CREATE TRIGGER fail_ack BEFORE UPDATE ON commands BEGIN SELECT RAISE(ABORT,'disk full'); END"); err != nil {
		t.Fatal(err)
	}
	if code := postPoll(t, s, cert, in); code != 500 {
		t.Fatal(code)
	}
	var ack sql.NullInt64
	s.st.DB.QueryRow("SELECT acked_at_ms FROM commands").Scan(&ack)
	if ack.Valid {
		t.Fatal("failed transaction ACKed")
	}
	if _, err := store.SettingDB(s.st.DB, "fw_status:a"); err != sql.ErrNoRows {
		t.Fatal("partial status survived", err)
	}
}
func TestPollChecksCurrentTrustAndMarksDelivery(t *testing.T) {
	s, _ := pollFixture(t)
	s.st.DB.Exec("UPDATE commands SET delivered_at_ms=NULL")
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Authorized || len(pr.Commands) != 1 {
		t.Fatal(pr)
	}
	var at sql.NullInt64
	s.st.DB.QueryRow("SELECT delivered_at_ms FROM commands").Scan(&at)
	if !at.Valid {
		t.Fatal("delivery not recorded")
	}
	s.st.DB.Exec("UPDATE agents SET trust_state='pending'")
	pr, err = s.pollSnapshot("a", "trusted", 0)
	if err != nil || pr.Authorized || len(pr.Commands) > 0 || pr.Mode != "" {
		t.Fatal("stale trust executed policy", pr, err)
	}
}

func TestPolicyReadFailureDoesNotBecomeEmptyPolicy(t *testing.T) {
	for _, table := range []string{"never_block", "ip_group_patterns", "policy_rules"} {
		t.Run(table, func(t *testing.T) {
			s, _ := pollFixture(t)
			if _, err := s.st.DB.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			if _, err := s.pollSnapshot("a", "trusted", 0); err == nil {
				t.Fatal("broken SQL became a valid policy")
			}
		})
	}
}
