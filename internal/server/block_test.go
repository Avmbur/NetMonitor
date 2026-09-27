package server_test

import (
	"path/filepath"
	"testing"
	"time"

	"netmonitor/internal/server"
	"netmonitor/internal/store"
)

func TestTrustAndBlock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	cfg := server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}
	if err := server.Init(cfg, "x"); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.DB.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES('h1','vm',1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.DB.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, display_name, first_seen_ms) VALUES('a1','h1','fp','pending','vm',1)`)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	n, err := server.TrustPending(dir, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("trusted %d", n)
	}
	id, err := server.BlockIP(dir, "1.1.1.1", time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("no id")
	}
	st, err = store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var state, cmdKind string
	if err := st.DB.QueryRow(`SELECT state FROM blocks WHERE block_id=?`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("state %s", state)
	}
	if err := st.DB.QueryRow(`SELECT kind FROM commands WHERE agent_id='a1'`).Scan(&cmdKind); err != nil {
		t.Fatal(err)
	}
	if cmdKind != "ban" {
		t.Fatalf("kind %s", cmdKind)
	}
}
