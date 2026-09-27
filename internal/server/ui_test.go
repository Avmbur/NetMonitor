package server_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"netmonitor/internal/server"
)

func TestLoginAndEmptyPark(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	cfg := server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}
	if err := server.Init(cfg, "secret"); err != nil {
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
	bad, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != 401 {
		t.Fatalf("bad login %d", bad.StatusCode)
	}
	st, err := cl.Get(base + "/ui/api/state")
	if err != nil {
		t.Fatal(err)
	}
	st.Body.Close()
	if st.StatusCode != 401 {
		t.Fatalf("state without sess %d", st.StatusCode)
	}
	ok, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	if ok.StatusCode != 200 {
		t.Fatalf("login %d", ok.StatusCode)
	}
	u, _ := url.Parse(base)
	if len(jar.Cookies(u)) == 0 {
		t.Fatal("no cookie")
	}
	st, err = cl.Get(base + "/ui/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Body.Close()
	if st.StatusCode != 200 {
		t.Fatalf("state %d", st.StatusCode)
	}
	var body struct {
		HasTrusted bool `json:"has_trusted"`
		Now        struct {
			Flows int `json:"flows"`
		} `json:"now"`
	}
	if err := json.NewDecoder(st.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.HasTrusted {
		t.Fatal("empty park expected")
	}
	if body.Now.Flows != 0 {
		t.Fatalf("now %d", body.Now.Flows)
	}
	home, err := cl.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	home.Body.Close()
	if home.StatusCode != 200 {
		t.Fatalf("index %d", home.StatusCode)
	}
}
