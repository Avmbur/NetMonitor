package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/tlsutil"
)

func TestVersionOrder(t *testing.T) {
	if !versionLess("1.0", "1.0.1") || !versionLess("1.9", "1.10") || versionLess("1.0", "1.0") || versionLess("2", "1.9") {
		t.Fatal("order")
	}
	if !versionOK("1.0") || versionOK("1.0a") || versionOK("") {
		t.Fatal("syntax")
	}
}

func TestParseReleaseRejectsForeignURL(t *testing.T) {
	body := []byte(`{"tag_name":"v1.2","assets":[{"name":"netmonitor-linux-amd64.tar.gz","browser_download_url":"https://evil.example/netmonitor-linux-amd64.tar.gz"}]}`)
	if _, err := parseRelease(body); err == nil {
		t.Fatal("foreign url accepted")
	}
	ok := []byte(`{"tag_name":"v1.2","body":"заметки","html_url":"https://github.com/Avmbur/NetMonitor/releases/tag/v1.2","assets":[{"name":"netmonitor-linux-amd64.tar.gz","browser_download_url":"https://github.com/Avmbur/NetMonitor/releases/download/v1.2/netmonitor-linux-amd64.tar.gz","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`)
	rel, err := parseRelease(ok)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "1.2" || rel.Assets["amd64"].URL == "" || len(rel.Assets["amd64"].SHA256) != 64 {
		t.Fatal(rel)
	}
}

func TestStageMonitorUpdateAndQueueAgents(t *testing.T) {
	s, cert := batchFixture(t)
	rel := releaseInfo{Version: "1.0", Assets: map[string]releaseAsset{"amd64": {URL: "https://github.com/Avmbur/NetMonitor/releases/download/v1.0/netmonitor-linux-amd64.tar.gz"}}}
	if _, err := s.stageMonitorUpdate(rel); err == nil {
		t.Fatal("same version staged")
	}
	rel.Version = "9.0"
	rel.Assets = map[string]releaseAsset{
		runtime.GOARCH: {URL: "https://github.com/Avmbur/NetMonitor/releases/download/v9.0/netmonitor-linux-" + runtime.GOARCH + ".tar.gz", SHA256: "ab"},
	}
	manual, err := s.stageMonitorUpdate(rel)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.dataDir(), "update.request"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "VERSION=9.0") || !strings.Contains(string(raw), "github.com/Avmbur/NetMonitor/releases/download/v9.0/") {
		t.Fatal(string(raw))
	}
	if !strings.Contains(manual, "--self-agent no") || strings.Contains(manual, "http://") {
		t.Fatal(manual)
	}
	s.st.DB.Exec(`UPDATE agents SET version='1.0'`)
	n, err := s.queueAgentUpdates(rel)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	n, err = s.queueAgentUpdates(rel)
	if err != nil || n != 0 {
		t.Fatal("second queue", n, err)
	}
	var id, kind string
	s.st.DB.QueryRow(`SELECT command_id, kind FROM commands`).Scan(&id, &kind)
	if kind != "update" || id == "" {
		t.Fatal(kind, id)
	}
	s.st.DB.Exec(`UPDATE agents SET policy_rev=2`)
	s.st.DB.Exec(`UPDATE commands SET delivered_at_ms=1, delivered_rev=2 WHERE command_id=?`, id)
	rev := int64(2)
	st := &protocol.ApplyStatus{Backend: "nftables", DesiredRev: 2, AppliedRev: &rev, CommandIDs: []string{id}}
	if code := postPoll(t, s, cert, protocol.PollReq{Rev: 2, Ack: []string{id}, Status: st}); code != 200 {
		t.Fatal(code)
	}
	var result string
	s.st.DB.QueryRow(`SELECT result FROM commands WHERE command_id=?`, id).Scan(&result)
	if result != "unsupported" {
		t.Fatal(result)
	}
	var left int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&left)
	if left != 1 {
		t.Fatal("agent row removed")
	}
}

func TestUpdateResultCompletesCommand(t *testing.T) {
	s, cert := batchFixture(t)
	fp := tlsutil.Fingerprint(cert.Raw)
	s.st.DB.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms,delivered_at_ms,delivered_rev) VALUES('up','a','update','{}',1,1,1)`)
	if err := s.recordUpdate(fp, "up", "failed", "нет места"); err != nil {
		t.Fatal(err)
	}
	if err := s.recordUpdate(fp, "up", "failed", "нет места"); err != nil {
		t.Fatal("lost failure response cannot be replayed", err)
	}
	if err := s.recordUpdate(fp, "up", "failed", "different error"); err == nil {
		t.Fatal("terminal failure overwritten")
	}
	var result, message string
	s.st.DB.QueryRow(`SELECT result, error FROM commands WHERE command_id='up'`).Scan(&result, &message)
	if result != "update_error" || message != "нет места" {
		t.Fatal(result, message)
	}
	if err := s.recordUpdate(fp, "up", "complete", ""); err == nil {
		t.Fatal("finished update accepted again")
	}
	s.st.DB.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms,delivered_at_ms,delivered_rev) VALUES('up2','a','update','{}',1,1,1)`)
	if err := s.recordUpdate("other", "up2", "complete", ""); err == nil {
		t.Fatal("foreign cert")
	}
	if err := s.recordUpdate(fp, "up2", "complete", ""); err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow(`SELECT result FROM commands WHERE command_id='up2'`).Scan(&result)
	if result != "applied" {
		t.Fatal(result)
	}
}

func TestUpdateSuccessRetryDoesNotDuplicateAudit(t *testing.T) {
	s, cert := batchFixture(t)
	fp := tlsutil.Fingerprint(cert.Raw)
	s.st.DB.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms,delivered_at_ms,delivered_rev) VALUES('up','a','update','{}',1,1,1)`)
	for range 2 {
		if err := s.recordUpdate(fp, "up", "complete", ""); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='обновил агента'").Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err := s.recordUpdate(fp, "up", "failed", "late rollback"); err == nil {
		t.Fatal("success overwritten")
	}
}
