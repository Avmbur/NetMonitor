//go:build linux

package collect

import (
	"net"
	"net/netip"
	"netmonitor/internal/protocol"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNFLOGKernelAndForeignVerdicts(t *testing.T) {
	if os.Getenv("NM_COLLECT_NETNS_TEST") != "1" {
		t.Skip("disposable network namespace")
	}
	run := func(input string, args ...string) string {
		t.Helper()
		c := exec.Command(args[0], args[1:]...)
		c.Stdin = strings.NewReader(input)
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("%v %v %s", args, e, b)
		}
		return string(b)
	}
	run("", "ip", "link", "set", "lo", "up")
	stop := make(chan struct{})
	defer close(stop)
	got := make(chan protocol.FirewallPayload, 100)
	errs := make(chan error, 10)
	go func() {
		errs <- ListenNFLog(stop, func(p protocol.FirewallPayload, e Entry) { got <- p }, func(e error) { errs <- e })
	}()
	script := "add table inet d3test\nadd chain inet d3test out { type filter hook output priority -100; policy accept; }\n"
	for _, s := range []string{"ip daddr 127.0.0.2 udp dport 9991 drop", "ip daddr 127.0.0.2 udp dport 9992 reject", "ip6 daddr ::1 udp dport 9993 drop", "ip6 daddr ::1 udp dport 9994 reject"} {
		script += "add rule inet d3test out " + s + "\n"
	}
	run(script, "nft", "-f", "-")
	if e := ObserveForeignFirewall(); e != nil {
		t.Fatal(e)
	}
	before := run("", "nft", "-j", "list", "table", "inet", "d3test")
	if e := ObserveForeignFirewall(); e != nil {
		t.Fatal(e)
	}
	if after := run("", "nft", "-j", "list", "table", "inet", "d3test"); after != before {
		t.Fatal("observer duplicated its own rules")
	}
	time.Sleep(250 * time.Millisecond)
	for _, addr := range []string{"127.0.0.2:9991", "127.0.0.2:9992", "[::1]:9993", "[::1]:9994"} {
		c, e := net.Dial("udp", addr)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = c.Write([]byte("probe"))
		c.Close()
	}
	seen := map[string]bool{}
	timeout := time.After(3 * time.Second)
	for len(seen) < 4 {
		select {
		case p := <-got:
			key := p.RemoteIP + "/" + p.Verdict
			seen[key] = true
			if p.Direction != "out" || p.Protocol != "udp" {
				t.Fatalf("%+v", p)
			}
		case e := <-errs:
			t.Fatal(e)
		case <-timeout:
			t.Fatalf("missing verdicts: %v", seen)
		}
	}
	// Deleting source rules removes only the observer mirrors, never adds accept/drop.
	run("flush chain inet d3test out\n", "nft", "-f", "-")
	if e := ObserveForeignFirewall(); e != nil {
		t.Fatal(e)
	}
}
func TestProcessLiveSocket(t *testing.T) {
	if os.Getenv("NM_COLLECT_NETNS_TEST") != "1" {
		t.Skip("Linux process test")
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	client, e := net.Dial("tcp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	src := client.LocalAddr().(*net.TCPAddr)
	dst := client.RemoteAddr().(*net.TCPAddr)
	sp, dp := src.Port, dst.Port
	entry := Entry{Protocol: "tcp", OrigSrc: netip.MustParseAddr(src.IP.String()), OrigDst: netip.MustParseAddr(dst.IP.String()), OrigSport: &sp, OrigDport: &dp}
	index := ProcessIndex{}
	p := index.Lookup(entry)
	if p.Comm == "" || p.Path == "" || p.UID == nil || *p.UID != os.Getuid() {
		t.Fatalf("socket not attributed: %+v", p)
	}
}
func TestConntrackSubscriptionReadyAndIdentity(t *testing.T) {
	if os.Getenv("NM_COLLECT_NETNS_TEST") != "1" {
		t.Skip("disposable network namespace")
	}
	if e := EnableKernel(); e != nil {
		t.Fatal(e)
	}
	if _, e := ConntrackFailures(); e != nil {
		t.Fatal(e)
	}
	stop := make(chan struct{})
	defer close(stop)
	ready := make(chan bool, 1)
	errs := make(chan error, 1)
	type obs struct {
		e Entry
		k string
	}
	events := make(chan obs, 200)
	go func() {
		errs <- WatchReady(stop, func(e Entry, k string) { events <- obs{e, k} }, func() { ready <- true })
	}()
	select {
	case <-ready:
	case e := <-errs:
		t.Fatal(e)
	case <-time.After(3 * time.Second):
		t.Fatal("subscription not ready")
	}
	// Bind both sides to keep this flow alive for the dump.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := net.Dial("tcp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	peer, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	port := l.Addr().(*net.TCPAddr).Port
	timeout := time.After(3 * time.Second)
	for {
		select {
		case e := <-errs:
			t.Fatal(e)
		case <-timeout:
			t.Fatal("no conntrack NEW")
		case o := <-events:
			if o.k != "new" || o.e.OrigDport == nil || *o.e.OrigDport != port {
				continue
			}
			if o.e.CTID == nil {
				t.Fatalf("kernel identity missing: %+v", o.e)
			}
			dump, e := DumpNetlink()
			if e != nil {
				t.Fatal(e)
			}
			for _, d := range dump {
				if d.CTID != nil && *d.CTID == *o.e.CTID {
					if d.StartNS <= 0 || o.e.StartNS > 0 && d.StartNS != o.e.StartNS {
						t.Fatal("dump identity changed")
					}
					return
				}
			}
			t.Fatal("NEW absent in dump")
		}
	}
}
