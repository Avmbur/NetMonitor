package svcnet

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func stubNet(t *testing.T, ips []netip.Addr) *[]string {
	t.Helper()
	oldLookup, oldDial := lookup, dial
	t.Cleanup(func() { lookup, dial = oldLookup, oldDial })
	var dialed []string
	lookup = func(context.Context, string) ([]netip.Addr, error) { return ips, nil }
	dial = func(_ context.Context, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c, s := net.Pipe()
		t.Cleanup(func() { c.Close(); s.Close() })
		return c, nil
	}
	return &dialed
}

func TestDialAdmitsBeforeConnecting(t *testing.T) {
	ip4 := netip.MustParseAddr("140.82.121.3")
	ip6 := netip.MustParseAddr("2606:50c0:8000::154")
	dialed := stubNet(t, []netip.Addr{netip.MustParseAddr("127.0.0.1"), ip4, ip6, ip4})
	var admitted []netip.Addr
	d := dialer(func(_ context.Context, ips []netip.Addr) error {
		if len(*dialed) != 0 {
			t.Fatal("connected before the address was admitted")
		}
		admitted = append(admitted, ips...)
		return nil
	})
	c, err := d(context.Background(), "tcp", "GitHub.com:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(admitted) != 2 || admitted[0] != ip4 || admitted[1] != ip6 {
		t.Fatalf("admitted %v: loopback or duplicate slipped in", admitted)
	}
	if len(*dialed) != 1 || (*dialed)[0] != "140.82.121.3:443" {
		t.Fatalf("dialed %v, not the admitted address", *dialed)
	}
}

func TestDialRefusesForeignTargetsAndFailedAdmit(t *testing.T) {
	dialed := stubNet(t, []netip.Addr{netip.MustParseAddr("140.82.121.3")})
	calls := 0
	d := dialer(func(context.Context, []netip.Addr) error { calls++; return nil })
	for _, addr := range []string{"example.com:443", "github.com:80", "github.com.evil.io:443", "140.82.121.3:443"} {
		if _, err := d(context.Background(), "tcp", addr); err == nil {
			t.Fatalf("%s allowed", addr)
		}
	}
	if calls != 0 || len(*dialed) != 0 {
		t.Fatal("foreign target admitted or dialed")
	}
	boom := errors.New("nft: no such table")
	d = dialer(func(context.Context, []netip.Addr) error { return boom })
	if _, err := d(context.Background(), "tcp", "api.github.com:443"); !errors.Is(err, boom) {
		t.Fatalf("admit failure hidden: %v", err)
	}
	if len(*dialed) != 0 {
		t.Fatal("connected although the filter refused the address")
	}
	stubNet(t, []netip.Addr{netip.MustParseAddr("::1")})
	if _, err := dialer(nil)(context.Background(), "tcp", "github.com:443"); err == nil {
		t.Fatal("name without a usable address dialed")
	}
}

func TestRedirectOnlyToGitHubOverHTTPS(t *testing.T) {
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	if err := checkRedirect(req("https://release-assets.githubusercontent.com/github-production-release-asset/1?sp=r"), nil); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"http://release-assets.githubusercontent.com/x",
		"https://release-assets.githubusercontent.com:8443/x",
		"https://evil.example/x",
	} {
		if err := checkRedirect(req(raw), nil); err == nil {
			t.Fatalf("%s followed", raw)
		}
	}
	via := make([]*http.Request, 5)
	if err := checkRedirect(req("https://github.com/x"), via); err == nil {
		t.Fatal("redirect loop followed")
	}
}

func TestClientNeverUsesProxyOrKeepAlive(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	c := Client(nil, time.Minute)
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || !tr.DisableKeepAlives || c.CheckRedirect == nil {
		t.Fatal("client can bypass the per-connection admission")
	}
}

func TestPayloadBounds(t *testing.T) {
	raw, err := Payload([]netip.Addr{netip.MustParseAddr("::ffff:140.82.121.3"), netip.MustParseAddr("2606:50c0:8000::154")})
	if err != nil {
		t.Fatal(err)
	}
	ips, ttl, err := ParsePayload(raw)
	if err != nil || len(ips) != 2 || ips[0].String() != "140.82.121.3" || ttl != AdmitTTL {
		t.Fatal(ips, ttl, err)
	}
	for _, bad := range []string{
		`{"ips":[],"ttl_ms":600000}`,
		`{"ips":["140.82.121.3"],"ttl_ms":1000}`,
		`{"ips":["140.82.121.3"],"ttl_ms":259200000}`,
		`{"ips":["127.0.0.1"],"ttl_ms":600000}`,
		`{"ips":["0.0.0.0"],"ttl_ms":600000}`,
		`{"ips":["github.com"],"ttl_ms":600000}`,
		`{"ips":["` + strings.Repeat(`1.1.1.1","`, maxAdmit) + `1.1.1.1"],"ttl_ms":600000}`,
	} {
		if _, _, err := ParsePayload(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestImportAdmitsHTTPSLinkBeforeConnecting(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	dialed := stubNet(t, []netip.Addr{ip})
	var admitted []netip.Addr
	admit := func(_ context.Context, ips []netip.Addr) error {
		// Каждое HTTPS-соединение — после своего вписывания, не раньше.
		if len(*dialed) != len(admitted) {
			t.Fatal("connected before the address was admitted")
		}
		admitted = append(admitted, ips...)
		return nil
	}
	d := ImportClient(admit, time.Minute).Transport.(*http.Transport).DialContext
	c, err := d(context.Background(), "tcp", "lists.example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(admitted) != 1 || admitted[0] != ip || (*dialed)[0] != "203.0.113.7:443" {
		t.Fatal(admitted, *dialed)
	}
	c, err = d(context.Background(), "tcp", "198.51.100.4:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(admitted) != 2 || admitted[1].String() != "198.51.100.4" {
		t.Fatal("literal HTTPS address not admitted", admitted)
	}
	c, err = d(context.Background(), "tcp", "lists.example.org:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(admitted) != 2 || (*dialed)[len(*dialed)-1] != "lists.example.org:80" {
		t.Fatal("plain HTTP changed behaviour", admitted, *dialed)
	}
	boom := errors.New("агент монитора не вписал адрес")
	d = ImportClient(func(context.Context, []netip.Addr) error { return boom }, time.Minute).Transport.(*http.Transport).DialContext
	n := len(*dialed)
	if _, err := d(context.Background(), "tcp", "lists.example.org:443"); !errors.Is(err, boom) || len(*dialed) != n {
		t.Fatal("import connected although the address was not admitted", err)
	}
}
