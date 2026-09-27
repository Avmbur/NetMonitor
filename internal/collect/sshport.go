package collect

import (
	"sort"
	"strings"
)

// SSHListenPort is the TCP port sshd binds beyond loopback. Factory sshd is 22.
func SSHListenPort(root string) int {
	ports := sshListenPorts(root)
	if len(ports) == 0 {
		return 22
	}
	sort.Ints(ports)
	for _, p := range ports {
		if p != 22 {
			return p
		}
	}
	return ports[0]
}

// SSHListenPorts lists every TCP port sshd binds beyond loopback, ascending.
func SSHListenPorts(root string) []int {
	ports := sshListenPorts(root)
	sort.Ints(ports)
	return ports
}

func sshListenPorts(root string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, l := range ListeningList(root) {
		if l.Proto != "tcp" || !isSSHD(l.Proc, l.Path) || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		ports = append(ports, l.Port)
	}
	return ports
}

func isSSHD(comm, path string) bool {
	c := strings.ToLower(comm)
	if c == "sshd" {
		return true
	}
	p := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	return strings.HasSuffix(p, "/sshd") || strings.HasSuffix(p, "/sshd.exe")
}
