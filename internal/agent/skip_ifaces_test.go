package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netmonitor/internal/store"
)

func TestLoadSkipIfaces(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := os.WriteFile(filepath.Join(dir, "skip-ifaces"), []byte("eth1\n#x\ndocker0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec("INSERT INTO meta(k,v) VALUES('skip_ifaces','wg0')"); err != nil {
		t.Fatal(err)
	}
	got := loadSkipIfaces(dir, st.DB)
	if !got["eth1"] || !got["docker0"] || !got["wg0"] || got["#x"] {
		t.Fatal(got)
	}
	note := (&Agent{skipIfaces: got}).scopeNote()
	for _, part := range []string{"virtio", "eth1", "docker0", "wg0"} {
		if !strings.Contains(note, part) {
			t.Fatal(note)
		}
	}
}
