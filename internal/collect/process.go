package collect

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Process struct {
	Comm, Path, Cgroup string
	UID                *int
}
type socketInfo struct {
	local, remote netip.AddrPort
	proto, inode  string
	uid           int
}
type ProcessIndex struct {
	Root     string
	mu       sync.Mutex
	at       time.Time
	sockets  []socketInfo
	owners   map[string]Process
	icmpProc Process
}

func (x *ProcessIndex) Lookup(e Entry) Process {
	x.mu.Lock()
	defer x.mu.Unlock()
	if time.Since(x.at) > 250*time.Millisecond {
		x.refresh()
	}
	if e.Protocol == "icmp" || e.Protocol == "icmpv6" {
		if x.icmpProc.Comm != "" {
			return x.icmpProc
		}
		return Process{}
	}
	dir, lip, rip, lp, rp := Classify(e, LocalAddrs())
	_ = dir
	if lp == nil {
		return Process{}
	}
	la, err := netip.ParseAddr(lip)
	if err != nil {
		return Process{}
	}
	ra, err := netip.ParseAddr(rip)
	if err != nil {
		return Process{}
	}
	var fallback Process
	for _, s := range x.sockets {
		if s.proto != e.Protocol || s.local.Port() != uint16(*lp) || s.local.Addr().Unmap() != la.Unmap() && !s.local.Addr().IsUnspecified() {
			continue
		}
		p, ok := x.owners[s.inode]
		if !ok {
			continue
		}
		if rp != nil && s.remote.Port() == uint16(*rp) && s.remote.Addr().Unmap() == ra.Unmap() {
			return p
		}
		if s.remote.Port() == 0 && s.remote.Addr().IsUnspecified() {
			fallback = p
		}
	}
	return fallback
}
func (x *ProcessIndex) refresh() {
	root := x.Root
	if root == "" {
		root = "/proc"
	}
	x.sockets = nil
	x.owners = map[string]Process{}
	x.icmpProc = Process{}
	x.at = time.Now()
	wanted := map[string]int{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "icmp", "icmp6", "raw", "raw6"} {
		b, err := os.ReadFile(filepath.Join(root, "net", name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			local, ok := procAddr(f[1])
			if !ok {
				continue
			}
			remote, ok := procAddr(f[2])
			if !ok {
				continue
			}
			uid, err := strconv.Atoi(f[7])
			if err != nil {
				continue
			}
			x.sockets = append(x.sockets, socketInfo{local, remote, strings.TrimSuffix(name, "6"), f[9], uid})
			wanted[f[9]] = uid
		}
	}
	procs, _ := os.ReadDir(root)
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		base := filepath.Join(root, p.Name())
		fds, err := os.ReadDir(filepath.Join(base, "fd"))
		if err != nil {
			continue
		}
		var inodes []string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(base, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := wanted[inode]; ok {
				inodes = append(inodes, inode)
			}
		}
		if len(inodes) == 0 {
			comm, _ := os.ReadFile(filepath.Join(base, "comm"))
			c := strings.TrimSpace(string(comm))
			if (c == "ping" || c == "ping6") && x.icmpProc.Comm == "" {
				path, _ := os.Readlink(filepath.Join(base, "exe"))
				x.icmpProc = Process{c, path, "", nil}
			}
			continue
		}
		path, _ := os.Readlink(filepath.Join(base, "exe"))
		comm, _ := os.ReadFile(filepath.Join(base, "comm"))
		cg, _ := os.ReadFile(filepath.Join(base, "cgroup"))
		group := ""
		for _, line := range strings.Split(string(cg), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[2] != "/" && (parts[1] == "" || strings.Contains(parts[1], "name=systemd")) {
				group = parts[2]
				break
			}
		}
		for _, inode := range inodes {
			u := wanted[inode]
			p := Process{strings.TrimSpace(string(comm)), path, group, &u}
			x.owners[inode] = p
			if p.Comm == "ping" || p.Comm == "ping6" {
				x.icmpProc = p
			}
		}
	}
}
func procAddr(s string) (netip.AddrPort, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, false
	}
	// /proc reports each 32-bit address word in native endian.
	for i := 0; i < len(raw); i += 4 {
		n := binary.NativeEndian.Uint32(raw[i : i+4])
		binary.BigEndian.PutUint32(raw[i:i+4], n)
	}
	ip, ok := netip.AddrFromSlice(raw)
	port, err := strconv.ParseUint(p, 16, 16)
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), ok && err == nil
}

// A reply of a local service leaves through the output hook, so a packet alone
// looks outgoing. The listening socket tells the real side of the conversation:
// a local port somebody listens on belongs to an inbound session.
type listenCache struct {
	mu    sync.Mutex
	at    time.Time
	ports map[string]bool
	root  string
}

var listeners = &listenCache{}

func (l *listenCache) has(proto string, port int) bool {
	if port <= 0 || proto != "tcp" && proto != "udp" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.at) > time.Second || l.ports == nil {
		l.refresh()
	}
	return l.ports[proto+"/"+strconv.Itoa(port)]
}

func (l *listenCache) refresh() {
	root := l.root
	if root == "" {
		root = "/proc"
	}
	l.at = time.Now()
	l.ports = map[string]bool{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join(root, "net", name))
		if err != nil {
			continue
		}
		proto := strings.TrimSuffix(name, "6")
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			local, ok := procAddr(f[1])
			if !ok {
				continue
			}
			remote, ok := procAddr(f[2])
			if !ok {
				continue
			}
			// TCP listen is state 0A; a UDP server socket has no peer.
			if proto == "tcp" && f[3] != "0A" || proto == "udp" && remote.Port() != 0 {
				continue
			}
			l.ports[proto+"/"+strconv.Itoa(int(local.Port()))] = true
		}
	}
}

// Listening reports a local service socket on this port.
func Listening(proto string, port int) bool { return listeners.has(proto, port) }
