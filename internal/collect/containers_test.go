package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerNamesByAddress(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "abc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"Name":"/web","NetworkSettings":{"IPAddress":"172.17.0.2","Networks":{"br":{"IPAddress":"172.18.0.2","GlobalIPv6Address":"fd00::2"}}}}`)
	if err := os.WriteFile(filepath.Join(dir, "config.v2.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	got := ContainerNames(root)
	if got["172.17.0.2"] != "web" || got["172.18.0.2"] != "web" || got["fd00::2"] != "web" {
		t.Fatal(got)
	}
}

func TestContainerNamesSkipMissingRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "id")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"Name":"/db","NetworkSettings":{"IPAddress":"172.18.0.3"}}`)
	if err := os.WriteFile(filepath.Join(dir, "config.v2.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range []string{filepath.Join(t.TempDir(), "missing"), root} {
		for ip, name := range readContainerDir(r) {
			got[ip] = name
		}
	}
	if got["172.18.0.3"] != "db" {
		t.Fatal(got)
	}
}

func TestRouteEvent(t *testing.T) {
	for _, typ := range []uint16{16, 17, 20, 21} {
		if !RouteEvent(typ) {
			t.Fatal(typ)
		}
	}
	if RouteEvent(0) || RouteEvent(22) {
		t.Fatal("other")
	}
}
