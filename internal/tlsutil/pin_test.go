package tlsutil

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPinnedBootstrapRejectsSubstitutionBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	pin, err := PublicKeyPin(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := PinnedTLSConfig(pin)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	r, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	bad, err := PinnedTLSConfig("sha256//" + strings.Repeat("A", 43) + "=")
	if err != nil {
		t.Fatal(err)
	}
	client.Transport = &http.Transport{TLSClientConfig: bad}
	if _, err = client.Get(server.URL); err == nil || calls.Load() != 1 {
		t.Fatal("substituted monitor received HTTP")
	}
	if _, err = PinnedTLSConfig(""); err == nil {
		t.Fatal("missing pin accepted")
	}
}
func TestServerKeyStableAcrossRestart(t *testing.T) {
	b, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("192.168.10.185")}
	if err = b.WriteServer(nil, ips); err != nil {
		t.Fatal(err)
	}
	before, err := PublicKeyPin(b.ServerTLS.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateCA(b.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = again.WriteServer(nil, ips); err != nil {
		t.Fatal(err)
	}
	after, _ := PublicKeyPin(again.ServerTLS.Certificate[0])
	if before != after {
		t.Fatal("restart rotated installation pin")
	}
}
