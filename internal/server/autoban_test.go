package server_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/agent"
	"netmonitor/internal/protocol"
	"netmonitor/internal/server"
	"netmonitor/internal/store"
)

func TestScanAutoban(t *testing.T) {
	dir := t.TempDir()
	srvDir := filepath.Join(dir, "srv")
	agDir := filepath.Join(dir, "ag")
	if err := server.Init(server.Config{DataDir: srvDir, ListenHost: "127.0.0.1", ListenPort: 8443}, "x"); err != nil {
		t.Fatal(err)
	}
	tok, err := server.NewToken(srvDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.Listen(server.Config{DataDir: srvDir, ListenHost: "127.0.0.1", ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.Serve() }()
	time.Sleep(80 * time.Millisecond)
	host, port, err := net.SplitHostPort(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	mon := net.JoinHostPort(host, port)
	a, err := agent.Open(agent.Config{DataDir: agDir, Monitor: mon, Token: tok, Pin: testPin(t, srvDir)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := server.TrustPending(srvDir, ""); err != nil {
		t.Fatal(err)
	}
	// Establish the volatile stream before observing the scan.
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("scan", 9, protocol.ScanPayload{IP: "203.0.113.50", Ports: []int{22, 80, 443, 3306, 8080}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(srvDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var reason, source string
	if err := st.DB.QueryRow(`SELECT reason, source FROM blocks WHERE remote_ip='203.0.113.50' AND state='active'`).Scan(&reason, &source); err != nil {
		t.Fatal(err)
	}
	if reason != "скан портов" || source != "scan" {
		t.Fatalf("reason=%s source=%s", reason, source)
	}
	var cmds int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM commands WHERE kind='ban'`).Scan(&cmds); err != nil {
		t.Fatal(err)
	}
	if cmds < 1 {
		t.Fatal("нет команды бана")
	}
	var rule, summary string
	if err := st.DB.QueryRow(`SELECT rule_id, summary FROM alerts WHERE closed_at_ms IS NULL`).Scan(&rule, &summary); err != nil {
		t.Fatal(err)
	}
	if rule != "scan" || !strings.Contains(summary, "203.0.113.50") || !strings.Contains(summary, "скан портов") {
		t.Fatalf("alert %s %s", rule, summary)
	}
}
