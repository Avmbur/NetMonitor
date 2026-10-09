package server_test

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netmonitor/internal/agent"
	"netmonitor/internal/protocol"
	"netmonitor/internal/server"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func TestInitAndBatchIdempotent(t *testing.T) {
	dir := t.TempDir()
	srvDir := filepath.Join(dir, "srv")
	agDir := filepath.Join(dir, "ag")
	cfg := server.Config{DataDir: srvDir, ListenHost: "127.0.0.1", ListenPort: 8443}
	if err := server.Init(cfg, "secret"); err != nil {
		t.Fatal(err)
	}
	if err := server.Init(cfg, "secret"); err == nil {
		t.Fatal("повторный init должен отказаться")
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
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve() }()
	select {
	case err := <-serveErr:
		t.Fatalf("serve: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

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

	dst := 443
	flow := protocol.FlowPayload{
		FlowUID:     "h1/b1/1/0/99/1",
		BootID:      "b1",
		IPVersion:   4,
		Protocol:    "tcp",
		OrigSrcIP:   "10.1.1.2",
		OrigDstIP:   "1.1.1.1",
		Direction:   "out",
		LocalIP:     "10.1.1.2",
		RemoteIP:    "1.1.1.1",
		FirstSeenMS: 1,
		LastSeenMS:  2,
		ReplySeen:   1,
		OrigDstPort: &dst,
		RemotePort:  &dst,
	}
	if err := a.Enqueue("flow", 5, flow); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	// А2: поток уже подтверждён и лежит в отложенной записи, пока монитор её не сбросит.

	st, err := store.OpenMonitor(srvDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM open_flows`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("open_flows=%d want 0", n)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("flows=%d want 0", n)
	}
	var ingestN int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM ingest_events`).Scan(&ingestN); err != nil {
		t.Fatal(err)
	}
	if ingestN != 0 {
		t.Fatalf("ingest=%d want 0", ingestN)
	}
	var trust string
	if err := st.DB.QueryRow(`SELECT trust_state FROM agents`).Scan(&trust); err != nil {
		t.Fatal(err)
	}
	if trust != "pending" {
		t.Fatalf("trust=%s", trust)
	}
	var contacts int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM v_contacts_out`).Scan(&contacts); err != nil {
		t.Fatal(err)
	}
	if contacts != 0 {
		t.Fatalf("v_contacts_out=%d want 0", contacts)
	}
	if _, err := agent.Open(agent.Config{DataDir: filepath.Join(dir, "ag2"), Monitor: mon, Token: tok, Pin: testPin(t, srvDir)}); err == nil {
		t.Fatal("повтор токена должен быть отказ")
	}
}

func TestPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	pi, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: pi}
	if err := server.Init(cfg, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Listen(cfg); err == nil {
		t.Fatal("ожидали занятый порт")
	}
}

func testPin(t *testing.T, dir string) string {
	t.Helper()
	b, err := tlsutil.LoadOrCreateCA(filepath.Join(dir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := tlsutil.PublicKeyPin(b.ServerTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return pin
}
