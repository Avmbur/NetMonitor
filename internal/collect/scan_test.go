package collect

import (
	"net/netip"
	"testing"
	"time"
)

func tcpIn(src string, dport int) Entry {
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr("192.168.10.180")
	sp, dp := 40000, dport
	return Entry{
		IPVersion: 4, Protocol: "tcp", State: "SYN_SENT",
		OrigSrc: s, OrigDst: d, OrigSport: &sp, OrigDport: &dp, Unreplied: true,
	}
}

func TestScanFivePorts(t *testing.T) {
	tr := NewTracker()
	local := []netip.Addr{netip.MustParseAddr("192.168.10.180")}
	now := time.Now()
	var hit *ScanHit
	for i, p := range []int{22, 80, 443, 3306, 8080} {
		h := tr.Observe(tcpIn("203.0.113.9", p), local, now.Add(time.Duration(i)*time.Second), 0)
		if h != nil {
			hit = h
		}
	}
	if hit == nil {
		t.Fatal("ждали скан")
	}
	if hit.IP.String() != "203.0.113.9" {
		t.Fatalf("ip %s", hit.IP)
	}
	if len(hit.Ports) < 5 {
		t.Fatalf("ports %v", hit.Ports)
	}
}

func TestScanSkipsMonitorPortAndCountsSYN(t *testing.T) {
	tr := NewTracker()
	local := []netip.Addr{netip.MustParseAddr("192.168.10.180")}
	now := time.Now()
	for i, p := range []int{22, 80, 443, 3306, 8443} {
		if h := tr.Observe(tcpIn("203.0.113.11", p), local, now.Add(time.Duration(i)*time.Second), 8443); h != nil {
			t.Fatal("monitor port counted as a scan")
		}
	}
	if h := tr.Observe(tcpIn("203.0.113.11", 8080), local, now.Add(6*time.Second), 8443); h == nil {
		t.Fatal("SYN without a session should complete a scan")
	}
}

func TestScanFourNoHit(t *testing.T) {
	tr := NewTracker()
	local := []netip.Addr{netip.MustParseAddr("192.168.10.180")}
	now := time.Now()
	for i, p := range []int{22, 80, 443, 3306} {
		if h := tr.Observe(tcpIn("203.0.113.10", p), local, now.Add(time.Duration(i)*time.Second), 0); h != nil {
			t.Fatalf("лишний скан %v", h)
		}
	}
}

func TestScanOnly443(t *testing.T) {
	tr := NewTracker()
	local := []netip.Addr{netip.MustParseAddr("192.168.10.180")}
	now := time.Now()
	for i := 0; i < 20; i++ {
		if h := tr.Observe(tcpIn("198.51.100."+itoa(i+1), 443), local, now.Add(time.Duration(i)*time.Millisecond), 0); h != nil {
			t.Fatal("посетители :443 не скан")
		}
	}
}
