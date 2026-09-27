package collect

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProcNet(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// sshd listens on :22 (state 0A), a client socket holds an ephemeral port.
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111\n" +
		"   1: B40AA8C0:CF7F 0102A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2222\n"
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestListeningPortNamesInboundSide(t *testing.T) {
	root := t.TempDir()
	writeProcNet(t, root)
	listeners.mu.Lock()
	listeners.root, listeners.at, listeners.ports = root, time.Time{}, nil
	listeners.mu.Unlock()
	t.Cleanup(func() {
		listeners.mu.Lock()
		listeners.root, listeners.at, listeners.ports = "", time.Time{}, nil
		listeners.mu.Unlock()
	})
	if !Listening("tcp", 22) {
		t.Fatal("listening port not seen")
	}
	if Listening("tcp", 53119) {
		t.Fatal("client socket counted as a listener")
	}
	local := netip.MustParseAddr("192.168.10.180")
	sp, dp := 22, 53119
	e := Entry{IPVersion: 4, Protocol: "tcp", OrigSrc: local, OrigDst: netip.MustParseAddr("192.168.10.185"), OrigSport: &sp, OrigDport: &dp}
	if dir, _, _, _, _ := Classify(e, []netip.Addr{local}); dir != "out" {
		t.Fatal("packet alone should look outgoing", dir)
	}
	dir, _, _, lp, rp := ClassifySession(e, []netip.Addr{local})
	if dir != "in" || lp == nil || *lp != 22 || rp == nil || *rp != 53119 {
		t.Fatal("reply of a local service still looks outgoing", dir, lp, rp)
	}
}
