package collect

import (
	"os"
	"path/filepath"
	"testing"
)

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
