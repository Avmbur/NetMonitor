package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"net/netip"
)

// Default container directories: a normal install and Docker from snap.
// A missing directory is skipped; it does not fail the other or the firewall.
var containerRoots = []string{
	"/var/lib/docker/containers",
	"/var/snap/docker/common/var-lib-docker/containers",
}

// ContainerNames maps a container address to its Docker name.
// root is one containers directory; empty reads every default root.
func ContainerNames(root string) map[string]string {
	if root != "" {
		return readContainerDir(root)
	}
	out := map[string]string{}
	for _, dir := range containerRoots {
		for ip, name := range readContainerDir(dir) {
			if _, ok := out[ip]; !ok {
				out[ip] = name
			}
		}
	}
	return out
}

func readContainerDir(root string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, ent.Name(), "config.v2.json"))
		if err != nil {
			continue
		}
		var cfg struct {
			Name            string `json:"Name"`
			NetworkSettings struct {
				IPAddress         string `json:"IPAddress"`
				GlobalIPv6Address string `json:"GlobalIPv6Address"`
				Networks          map[string]struct {
					IPAddress         string `json:"IPAddress"`
					GlobalIPv6Address string `json:"GlobalIPv6Address"`
				} `json:"Networks"`
			} `json:"NetworkSettings"`
		}
		if json.Unmarshal(b, &cfg) != nil {
			continue
		}
		name := strings.TrimPrefix(cfg.Name, "/")
		if name == "" {
			continue
		}
		add := func(s string) {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return
			}
			out[a.Unmap().String()] = name
		}
		add(cfg.NetworkSettings.IPAddress)
		add(cfg.NetworkSettings.GlobalIPv6Address)
		for _, n := range cfg.NetworkSettings.Networks {
			add(n.IPAddress)
			add(n.GlobalIPv6Address)
		}
	}
	return out
}
