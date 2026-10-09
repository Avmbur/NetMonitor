package tlsutil

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRestoreTrustKeepsCA(t *testing.T) {
	root := t.TempDir()
	t.Setenv("NM_TRUST_DIR", filepath.Join(root, "backup"))
	first := filepath.Join(root, "old")
	b, err := LoadOrCreateCA(filepath.Join(first, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	if err := MirrorTrust(first); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, "new")
	if err := RestoreTrust(second); err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateCA(filepath.Join(second, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.CACert.Raw, again.CACert.Raw) {
		t.Fatal("новый монитор выпустил другой центр")
	}
}
