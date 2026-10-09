package agent

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"netmonitor/internal/tlsutil"
)

func TestRebindDoesNotTrustStranger(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte(`{"status":"ready","pin":"sha256//not-the-server","token":"tok"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	b, err := tlsutil.LoadOrCreateCA(filepath.Join(dir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _, err := b.IssueClient("box")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls", "client.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls", "client.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{DataDir: dir, Monitor: srv.URL}}
	if err := a.rebindIfReplaced(); err == nil {
		t.Fatal("чужой сервер принят")
	}
	if hit {
		t.Fatal("запрос ушёл на непроверенный сервер")
	}
}
