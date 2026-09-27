package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ListeningPorts counts protocol/port pairs bound beyond loopback.
// IPv4/IPv6 listeners on the same port count once; reachability is not implied.
func ListeningPorts(root string) (*int, error) {
	if root == "" {
		root = "/proc"
	}
	ports := map[string]bool{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join(root, "net", name))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			local, ok := procAddr(f[1])
			if !ok || local.Port() == 0 || local.Addr().IsLoopback() {
				continue
			}
			remote, ok := procAddr(f[2])
			if !ok {
				continue
			}
			proto := strings.TrimSuffix(name, "6")
			if proto == "tcp" && f[3] != "0A" {
				continue
			}
			if proto == "udp" && (!remote.Addr().IsUnspecified() || remote.Port() != 0) {
				continue
			}
			ports[fmt.Sprintf("%s/%d", proto, local.Port())] = true
		}
	}
	n := len(ports)
	return &n, nil
}
