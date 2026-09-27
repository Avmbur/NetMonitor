package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

func TestRepeatTokenKeepsKnownAgent(t *testing.T) {
	enrolls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enroll" {
			enrolls++
			http.Error(w, "enroll", 500)
			return
		}
		if r.URL.Path == "/v1/poll" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authorized":false,"policy_rev":1}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := enrolledAgent(t, dir, srv)
	pin, err := tlsutil.PublicKeyPin(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Token = "second-token"
	a.cfg.ForceEnroll = true
	a.cfg.Pin = pin
	a.cfg.Monitor = srv.URL
	if err := a.ensureEnrolled(); err != nil {
		t.Fatal(err)
	}
	if !a.AlreadyKnown() {
		t.Fatal("known agent was enrolled again")
	}
	if enrolls != 0 {
		t.Fatalf("enroll calls %d", enrolls)
	}
	id, err := meta(a.st.DB, "agent_id")
	if err != nil || id != "agent-1" {
		t.Fatalf("id %q err %v", id, err)
	}
}

func TestRevokedAgentUsesNewToken(t *testing.T) {
	enrolls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			enrolls++
			http.Error(w, "stop after enroll", 400)
		case "/v1/poll":
			http.Error(w, "отозван", http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := enrolledAgent(t, dir, srv)
	pin, err := tlsutil.PublicKeyPin(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Token = "fresh"
	a.cfg.ForceEnroll = true
	a.cfg.Pin = pin
	a.cfg.Monitor = srv.URL
	if err := a.ensureEnrolled(); err == nil || enrolls != 1 {
		t.Fatalf("err %v enrolls %d", err, enrolls)
	}
	if a.AlreadyKnown() {
		t.Fatal("revoked agent was kept")
	}
}

func TestUnknownCertificateUsesNewToken(t *testing.T) {
	got := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/poll" {
			got = true
			http.Error(w, "неизвестный сертификат", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	a := enrolledAgent(t, t.TempDir(), srv)
	pin, err := tlsutil.PublicKeyPin(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Pin = pin
	a.cfg.Monitor = srv.URL
	keep, err := a.keepIfKnown()
	if err != nil || keep || !got {
		t.Fatalf("keep %v err %v polled %v", keep, err, got)
	}
}

func TestPinMismatchDoesNotEnroll(t *testing.T) {
	enrolls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enroll" {
			enrolls++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	a := enrolledAgent(t, t.TempDir(), srv)
	sum := sha256.Sum256([]byte("other-monitor"))
	a.cfg.Token = "fresh"
	a.cfg.ForceEnroll = true
	a.cfg.Pin = "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
	a.cfg.Monitor = srv.URL
	if err := a.ensureEnrolled(); err == nil {
		t.Fatal("wrong pin was accepted")
	}
	if enrolls != 0 {
		t.Fatalf("enroll calls %d", enrolls)
	}
	if a.AlreadyKnown() {
		t.Fatal("kept despite pin mismatch")
	}
}

func TestUnreachableMonitorDoesNotEnroll(t *testing.T) {
	enrolls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrolls++
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close()
	a := enrolledAgent(t, t.TempDir(), srv)
	pin, err := tlsutil.PublicKeyPin(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Token = "fresh"
	a.cfg.ForceEnroll = true
	a.cfg.Pin = pin
	a.cfg.Monitor = srv.URL
	if err := a.ensureEnrolled(); err == nil {
		t.Fatal("closed monitor was accepted")
	}
	if enrolls != 0 || a.AlreadyKnown() {
		t.Fatalf("enrolls %d kept %v", enrolls, a.AlreadyKnown())
	}
}

func TestReplacedMonitorKeyEnrollsAgain(t *testing.T) {
	polled := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/poll" {
			polled = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := enrolledAgent(t, dir, srv)
	// httptest servers share one certificate, so a second server is not a new key.
	writeCert(t, filepath.Join(dir, "tls", "ca.crt"), freshCA(t))
	pin, err := tlsutil.PublicKeyPin(srv.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Pin = pin
	a.cfg.Monitor = srv.URL
	keep, err := a.keepIfKnown()
	if err != nil || keep || polled {
		t.Fatalf("keep %v err %v polled %v", keep, err, polled)
	}
}

func enrolledAgent(t *testing.T, dir string, srv *httptest.Server) *Agent {
	t.Helper()
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Update(func(tx *sql.Tx) error {
		for _, kv := range [][2]string{{"agent_id", "agent-1"}, {"host_id", "host-1"}, {"monitor", srv.URL}} {
			if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?)`, kv[0], kv[1]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCert(t, filepath.Join(tlsDir, "ca.crt"), srv.Certificate())
	writeClientPair(t, tlsDir)
	return &Agent{st: st, cfg: Config{DataDir: dir, Monitor: srv.URL}}
}

func freshCA(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "other-monitor"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeCert(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeClientPair(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
