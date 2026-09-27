package server_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"testing"
	"time"

	"netmonitor/internal/server"
	"netmonitor/internal/store"
)

func TestGroupBlockSaved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	if err := server.Init(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}, "x"); err != nil {
		t.Fatal(err)
	}
	s, err := server.Listen(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.Serve() }()
	time.Sleep(80 * time.Millisecond)
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}},
		Jar:       jar,
		Timeout:   5 * time.Second,
	}
	base := "https://" + s.Addr()
	ok, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	body, _ := json.Marshal(map[string]any{"name": "тест", "policy": "block", "members": "9.9.9.9\n1.2.3.0/24"})
	r, err := cl.Post(base+"/ui/api/groups", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("groups %d", r.StatusCode)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM ip_groups WHERE policy='block'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("groups %d", n)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM ip_group_members`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("members %d", n)
	}
}
