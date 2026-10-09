package collect

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSocketProc(t *testing.T, root, pid, comm, inode, netfile, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := os.WriteFile(filepath.Join(root, "net", netfile), []byte(hdr+body), 0o644); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, pid)
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(base, "fd", "3")); err != nil {
		t.Fatal(err)
	}
}

func TestICMPLookupFindsPing(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(hdr), 0o644); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "4242")
	if err := os.MkdirAll(filepath.Join(base, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "comm"), []byte("ping\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := ProcessIndex{Root: root}
	p := idx.Lookup(Entry{Protocol: "icmp"})
	if p.Comm != "ping" {
		t.Fatalf("icmp ping %+v", p)
	}
	if got := idx.Lookup(Entry{Protocol: "tcp"}).Comm; got != "" {
		t.Fatalf("tcp used icmp owner %q", got)
	}
}

func TestDNSProcessSurvivesClosedSocket(t *testing.T) {
	root := t.TempDir()
	// 0.0.0.0:9999 -> 192.168.10.10:53, inode 3333.
	writeSocketProc(t, root, "7", "systemd-resolve", "3333", "udp",
		"   0: 00000000:270F 0A0AA8C0:0035 01 00000000:00000000 00:00000000 00000000   990        0 3333\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	lp, rp := 9999, 53
	e := Entry{Protocol: "udp", OrigSrc: netip.MustParseAddr("10.1.1.1"), OrigDst: netip.MustParseAddr("192.168.10.10"), OrigSport: &lp, OrigDport: &rp}
	idx.mu.Lock()
	idx.refresh()
	p, ok := idx.match(e, local)
	idx.mu.Unlock()
	if !ok || p.Comm != "systemd-resolve" {
		t.Fatalf("live socket %+v ok=%v", p, ok)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "udp"), []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root, "7", "fd", "3"))
	idx.mu.Lock()
	idx.refresh()
	got, ok := idx.exact(e, local)
	idx.mu.Unlock()
	// The same flow was seen with its owner: policy may use the full identity.
	if !ok || got.Comm != "systemd-resolve" || got.UID == nil || *got.UID != 990 {
		t.Fatalf("closed dns socket lost process %+v ok=%v", got, ok)
	}
}

func TestPeerGuessIsDisplayOnly(t *testing.T) {
	root := t.TempDir()
	writeSocketProc(t, root, "7", "systemd-resolve", "3333", "udp",
		"   0: 00000000:270F 0A0AA8C0:0035 01 00000000:00000000 00:00000000 00000000   990        0 3333\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.refresh()
	// Another program asked the same resolver from a port nobody saw.
	lp, rp := 41000, 53
	e := Entry{Protocol: "udp", OrigSrc: netip.MustParseAddr("10.1.1.1"), OrigDst: netip.MustParseAddr("192.168.10.10"), OrigSport: &lp, OrigDport: &rp}
	if p, ok := idx.exact(e, local); ok || p.Comm != "" {
		t.Fatalf("policy got a guessed owner %+v", p)
	}
	g := idx.recall(e, local)
	if g.Comm != "systemd-resolve" || g.Path != "" || g.Cgroup != "" || g.UID != nil {
		t.Fatalf("display guess must carry only the name: %+v", g)
	}
	// Two programs behind one peer: nobody is named.
	idx.rememberSock(socketInfo{netip.MustParseAddrPort("10.1.1.1:42000"), netip.MustParseAddrPort("192.168.10.10:53"), "udp", "5555", 0}, Process{Comm: "dig", Path: "/usr/bin/dig"}, time.Now())
	if g := idx.recall(e, local); g.Comm != "" {
		t.Fatalf("mixed peer still guessed %+v", g)
	}
}

func TestWatchFindsShortUDPWithoutFullWalk(t *testing.T) {
	root := t.TempDir()
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	// The resolver listens; that makes it a UDP owner worth watching.
	writeSocketProc(t, root, "7", "systemd-resolve", "3333", "udp",
		"   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 3333\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.refresh()
	at := idx.at
	// A query socket opens and closes between two full walks.
	if err := os.Symlink("socket:[4444]", filepath.Join(root, "7", "fd", "4")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "udp"), []byte(hdr+
		"   0: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 3333\n"+
		"   1: 0101010A:A028 0A0AA8C0:0035 01 00000000:00000000 00:00000000 00000000   990        0 4444\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx.watchUDP()
	if !idx.at.Equal(at) {
		t.Fatal("watch pass walked all of /proc")
	}
	lp, rp := 41000, 53
	e := Entry{Protocol: "udp", OrigSrc: netip.MustParseAddr("10.1.1.1"), OrigDst: netip.MustParseAddr("192.168.10.10"), OrigSport: &lp, OrigDport: &rp}
	idx.sockets = nil
	if p, ok := idx.exact(e, local); !ok || p.Comm != "systemd-resolve" {
		t.Fatalf("short query lost its owner %+v ok=%v", p, ok)
	}
}

func TestLookupMissDoesNotWalkAgain(t *testing.T) {
	root := t.TempDir()
	writeSocketProc(t, root, "9", "sshd", "1111", "tcp",
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.refresh()
	at := idx.at
	// A scan to closed ports: every packet misses, none may cost a /proc walk.
	for port := 1000; port < 1100; port++ {
		sp, dp := 40000, port
		e := Entry{Protocol: "tcp", OrigSrc: netip.MustParseAddr("203.0.113.9"), OrigDst: netip.MustParseAddr("10.1.1.1"), OrigSport: &sp, OrigDport: &dp}
		if _, ok := idx.exact(e, local); ok {
			t.Fatalf("closed port %d has an owner", port)
		}
	}
	if !idx.at.Equal(at) && time.Since(at) < procRefresh {
		t.Fatal("a miss walked /proc again")
	}
}

func TestUnconnectedDNSPortIsRemembered(t *testing.T) {
	root := t.TempDir()
	writeSocketProc(t, root, "8", "systemd-resolve", "4444", "udp",
		"   0: 00000000:270F 00000000:0000 07 00000000:00000000 00:00000000 00000000   990        0 4444\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	lp, rp := 9999, 53
	e := Entry{Protocol: "udp", OrigSrc: netip.MustParseAddr("10.1.1.1"), OrigDst: netip.MustParseAddr("192.168.10.10"), OrigSport: &lp, OrigDport: &rp}
	idx.mu.Lock()
	idx.refresh()
	if err := os.WriteFile(filepath.Join(root, "net", "udp"), []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root, "8", "fd", "3"))
	idx.refresh()
	got := idx.recall(e, local)
	idx.mu.Unlock()
	if got.Comm != "systemd-resolve" {
		t.Fatalf("unconnected dns %+v", got)
	}
}

func TestInboundUsesListenerWhenEstablishedSocketHasNoOwner(t *testing.T) {
	root := t.TempDir()
	writeSocketProc(t, root, "9", "sshd", "1111", "tcp",
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111\n")
	idx := ProcessIndex{Root: root}
	local := []netip.Addr{netip.MustParseAddr("10.1.1.1")}
	sp, dp := 40000, 22
	// Client opened the session. The accepted socket is already gone; the listener remains.
	e := Entry{Protocol: "tcp", OrigSrc: netip.MustParseAddr("203.0.113.9"), OrigDst: netip.MustParseAddr("10.1.1.1"), OrigSport: &sp, OrigDport: &dp}
	idx.mu.Lock()
	idx.refresh()
	p, ok := idx.match(e, local)
	idx.mu.Unlock()
	if !ok || p.Comm != "sshd" {
		t.Fatalf("listener %+v ok=%v", p, ok)
	}
	if time.Until(idx.recent[listenKey("tcp", 22)].until) <= 0 {
		t.Fatal("listener was not remembered")
	}
}
