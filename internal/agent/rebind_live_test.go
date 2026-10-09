package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/server"
	"netmonitor/internal/tlsutil"
)

func startMonitor(t *testing.T, dir string) *server.Server {
	t.Helper()
	cfg := server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}
	if err := server.Init(cfg, "secret"); err != nil {
		t.Fatal(err)
	}
	s, err := server.Listen(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	time.Sleep(50 * time.Millisecond)
	return s
}

func pinOf(t *testing.T, dir string) string {
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

func adminClient(t *testing.T, raw string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}},
		Jar:       jar,
		Timeout:   5 * time.Second,
	}
	base := "https://" + raw
	res, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("login %d", res.StatusCode)
	}
	return cl
}

func TestInstallOnNewMonitorIgnoresOldCertificate(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "old")
	newDir := filepath.Join(root, "new")
	agDir := filepath.Join(root, "ag")
	oldSrv := startMonitor(t, oldDir)
	tok, err := server.NewToken(oldDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(Config{DataDir: agDir, Monitor: oldSrv.Addr(), Token: tok, Pin: pinOf(t, oldDir)})
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	oldSrv.Close()

	newSrv := startMonitor(t, newDir)
	defer newSrv.Close()
	tok, err = server.NewToken(newDir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Open(Config{DataDir: agDir, Monitor: newSrv.Addr(), Token: tok, Pin: pinOf(t, newDir), ForceEnroll: true})
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}

func TestRebindAfterReinstallUsesRealTLS(t *testing.T) {
	root := t.TempDir()
	srvDir := filepath.Join(root, "srv")
	agDir := filepath.Join(root, "ag")
	s := startMonitor(t, srvDir)
	tok, err := server.NewToken(srvDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(Config{DataDir: agDir, Monitor: s.Addr(), Token: tok, Pin: pinOf(t, srvDir)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	s.Close()

	for _, name := range []string{"netmon.sqlite", "netmon.sqlite-wal", "netmon.sqlite-shm"} {
		_ = os.Remove(filepath.Join(srvDir, name))
	}
	_ = os.Remove(filepath.Join(srvDir, "tls", "server.crt"))
	_ = os.Remove(filepath.Join(srvDir, "tls", "server.key"))
	s = startMonitor(t, srvDir)
	defer s.Close()
	a.cfg.Monitor = s.Addr()

	err = a.rebindIfReplaced()
	if err == nil || !strings.Contains(err.Error(), "ждёт переподключения") {
		t.Fatalf("до кнопки: %v", err)
	}
	cl := adminClient(t, s.Addr())
	base := "https://" + s.Addr()
	res, err := cl.Get(base + "/ui/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Knocks []struct {
			IP string `json:"ip"`
		} `json:"knocks"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		res.Body.Close()
		t.Fatal(err)
	}
	res.Body.Close()
	if len(body.Knocks) != 1 || body.Knocks[0].IP == "" {
		t.Fatalf("стуки %+v", body.Knocks)
	}
	res, err = cl.Post(base+"/ui/api/rebind", "application/json", bytes.NewBufferString(`{"ip":"`+body.Knocks[0].IP+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("кнопка %d", res.StatusCode)
	}
	if err := a.rebindIfReplaced(); err != nil {
		t.Fatal(err)
	}
	res, err = cl.Get(base + "/ui/api/state")
	if err != nil {
		t.Fatal(err)
	}
	body.Knocks = nil
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		res.Body.Close()
		t.Fatal(err)
	}
	res.Body.Close()
	if len(body.Knocks) != 0 {
		t.Fatalf("строка осталась: %+v", body.Knocks)
	}
	u, _ := url.Parse(base)
	if cl.Jar.Cookies(u) == nil {
		t.Fatal("сессия пропала")
	}
}
