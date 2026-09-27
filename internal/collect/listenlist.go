package collect

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Listener is one TCP/UDP port bound beyond loopback.
type Listener struct {
	Proto, Proc, Path, Desc string
	Port                    int
}

// ListeningList lists protocol/port pairs bound beyond loopback, with the process if known.
func ListeningList(root string) []Listener {
	if root == "" {
		root = "/proc"
	}
	type key struct {
		proto string
		port  int
	}
	inodeKey := map[string]key{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join(root, "net", name))
		if err != nil {
			continue
		}
		proto := strings.TrimSuffix(name, "6")
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
			if proto == "tcp" && f[3] != "0A" {
				continue
			}
			if proto == "udp" && (!remote.Addr().IsUnspecified() || remote.Port() != 0) {
				continue
			}
			inodeKey[f[9]] = key{proto, int(local.Port())}
		}
	}
	by := map[key]Listener{}
	for _, k := range inodeKey {
		by[k] = Listener{Proto: k.proto, Port: k.port}
	}
	ents, err := os.ReadDir(root)
	if err == nil {
		for _, ent := range ents {
			if _, err := strconv.Atoi(ent.Name()); err != nil {
				continue
			}
			base := filepath.Join(root, ent.Name())
			fds, err := os.ReadDir(filepath.Join(base, "fd"))
			if err != nil {
				continue
			}
			comm, _ := os.ReadFile(filepath.Join(base, "comm"))
			path, _ := os.Readlink(filepath.Join(base, "exe"))
			proc := strings.TrimSpace(string(comm))
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
				if err != nil || !strings.HasPrefix(target, "socket:[") {
					continue
				}
				inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				k, ok := inodeKey[inode]
				if !ok {
					continue
				}
				cur := by[k]
				if cur.Proc == "" || isInitProc(cur.Proc) && !isInitProc(proc) {
					cur.Proc, cur.Path = proc, path
					by[k] = cur
				}
			}
		}
	}
	out := make([]Listener, 0, len(by))
	for _, l := range by {
		if isInitProc(l.Proc) {
			if name, pth := socketService(l.Proto, l.Port); name != "" {
				l.Proc, l.Path = name, pth
			}
		}
		l.Desc = serviceName(l.Proto, l.Port)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}
