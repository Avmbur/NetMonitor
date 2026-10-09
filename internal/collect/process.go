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
	// recent remembers a socket after it closes. A DNS query is gone from /proc
	// before conntrack reports the flow; the name is still the one we just saw.
	recent map[string]seenProc
	// peers — who talked to a remote address and port lately; mixed means more
	// than one program, and then nobody is named by the peer alone.
	peers map[string]seenPeer
	// udpPids own UDP sockets; the watch pass looks only into them.
	udpPids   map[string]bool
	udpOwners map[string]Process
	unowned   map[string]bool
	touched   time.Time
	pruned    time.Time
}

type seenProc struct {
	p     Process
	until time.Time
}

type seenPeer struct {
	p     Process
	until time.Time
	mixed bool
}

const (
	procRemember = 3 * time.Minute
	// A full /proc walk costs milliseconds; four per second at most, so a burst
	// of unknown packets cannot turn lookups into a busy loop.
	procRefresh = 250 * time.Millisecond
	watchEvery  = 40 * time.Millisecond
)

// Lookup names the program for display. When the socket is already gone it
// falls back to the listener seen on that port or the only program seen with
// that peer: a likely name, not proof. Policy uses LookupExact.
func (x *ProcessIndex) Lookup(e Entry) Process {
	x.mu.Lock()
	defer x.mu.Unlock()
	local := LocalAddrs()
	if p, ok := x.exact(e, local); ok {
		return p
	}
	return x.recall(e, local)
}

// LookupExact returns only an owner seen with this very flow: a live socket,
// the current listener of the port, or the same socket just closed. A rule or
// a question bound to a program must not take a guess for it.
func (x *ProcessIndex) LookupExact(e Entry) Process {
	x.mu.Lock()
	defer x.mu.Unlock()
	p, _ := x.exact(e, LocalAddrs())
	return p
}

func (x *ProcessIndex) exact(e Entry, local []netip.Addr) (Process, bool) {
	if x.at.IsZero() || time.Since(x.at) > procRefresh {
		x.refresh()
	}
	if p, ok := x.match(e, local); ok {
		return p, true
	}
	f, ok := endsOf(e, local)
	if !ok {
		return Process{}, false
	}
	if s, ok := x.recent[flowKey(f.proto, f.lp, f.ra, f.rp)]; ok && time.Now().Before(s.until) {
		return s.p, true
	}
	return Process{}, false
}

// Watch samples UDP sockets often enough that a short DNS query is remembered
// before conntrack publishes the flow.
func (x *ProcessIndex) Watch(stop <-chan struct{}) {
	tick := time.NewTicker(watchEvery)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			x.mu.Lock()
			x.watchUDP()
			x.mu.Unlock()
		}
	}
}

// watchUDP is the cheap pass between full walks: two small tables and the fd
// lists of programs that already own UDP sockets. Walking all of /proc 25
// times a second costs about a sixth of a core.
func (x *ProcessIndex) watchUDP() {
	if x.at.IsZero() {
		x.refresh()
		return
	}
	root := x.procRoot()
	now := time.Now()
	// Known sockets are re-stamped every few seconds, new ones at once.
	touch := now.Sub(x.touched) > 5*time.Second
	if touch {
		x.touched = now
	}
	owners := map[string]Process{}
	unowned := map[string]bool{}
	want := map[string]socketInfo{}
	for _, name := range []string{"udp", "udp6"} {
		for _, s := range readSockets(root, name) {
			if x.unowned[s.inode] {
				unowned[s.inode] = true
				continue
			}
			p, ok := x.udpOwners[s.inode]
			if ok && !touch {
				owners[s.inode] = p
				continue
			}
			if !ok {
				p, ok = x.owners[s.inode]
			}
			if ok {
				owners[s.inode] = p
				x.rememberSock(s, p, now)
				continue
			}
			want[s.inode] = s
		}
	}
	for pid := range x.udpPids {
		if len(want) == 0 {
			break
		}
		base := filepath.Join(root, pid)
		fds, err := os.ReadDir(filepath.Join(base, "fd"))
		if err != nil {
			delete(x.udpPids, pid)
			continue
		}
		for _, fd := range fds {
			inode, ok := socketInode(filepath.Join(base, "fd", fd.Name()))
			if !ok {
				continue
			}
			s, ok := want[inode]
			if !ok {
				continue
			}
			p := x.serviceProc(s.proto, int(s.local.Port()), procInfo(base, s.uid))
			owners[inode] = p
			x.rememberSock(s, p, now)
			delete(want, inode)
		}
	}
	// A kernel socket or a program outside the watched set: look again only on
	// the next full walk, not on every tick.
	for inode := range want {
		unowned[inode] = true
	}
	x.udpOwners, x.unowned = owners, unowned
	if now.Sub(x.pruned) > 10*time.Second {
		x.prune(now)
	}
}

func (x *ProcessIndex) match(e Entry, local []netip.Addr) (Process, bool) {
	if e.Protocol == "icmp" || e.Protocol == "icmpv6" {
		if x.icmpProc.Comm != "" {
			return x.icmpProc, true
		}
		return Process{}, false
	}
	f, ok := endsOf(e, local)
	if !ok {
		return Process{}, false
	}
	now := time.Now()
	var fallback Process
	var found bool
	for _, s := range x.sockets {
		if s.proto != f.proto || s.local.Port() != uint16(f.lp) || s.local.Addr().Unmap() != f.la && !s.local.Addr().IsUnspecified() {
			continue
		}
		p, ok := x.owners[s.inode]
		if !ok {
			continue
		}
		p = x.serviceProc(s.proto, int(s.local.Port()), p)
		if f.rp > 0 && s.remote.Port() == uint16(f.rp) && s.remote.Addr().Unmap() == f.ra {
			x.rememberSock(s, p, now)
			return p, true
		}
		if s.remote.Port() == 0 && s.remote.Addr().IsUnspecified() {
			fallback, found = p, true
		}
	}
	if found {
		x.remember(listenKey(f.proto, f.lp), fallback, now)
		return fallback, true
	}
	return Process{}, false
}

// recall gives a likely name for display only. It carries no path, cgroup or
// uid, so neither a rule nor a rule made from this row can bind to it.
func (x *ProcessIndex) recall(e Entry, local []netip.Addr) Process {
	f, ok := endsOf(e, local)
	if !ok {
		return Process{}
	}
	now := time.Now()
	// A client socket with no peer is stored under the local port. The flow
	// later shows the resolver it actually talked to.
	if s, ok := x.recent[listenKey(f.proto, f.lp)]; ok && now.Before(s.until) {
		return Process{Comm: s.p.Comm}
	}
	// The exact ephemeral port was already gone. One program sending to this
	// peer is most likely the sender: that is how short DNS queries look.
	if f.rp > 0 {
		if s, ok := x.peers[peerKey(f.proto, f.ra, f.rp)]; ok && !s.mixed && now.Before(s.until) {
			return Process{Comm: s.p.Comm}
		}
	}
	return Process{}
}

type flowEnds struct {
	proto  string
	la, ra netip.Addr
	lp, rp int
}

func endsOf(e Entry, local []netip.Addr) (flowEnds, bool) {
	if e.Protocol == "icmp" || e.Protocol == "icmpv6" {
		return flowEnds{}, false
	}
	_, lip, rip, lp, rp := ClassifyNets(e, local, nil)
	if lp == nil {
		return flowEnds{}, false
	}
	la, err1 := netip.ParseAddr(lip)
	ra, err2 := netip.ParseAddr(rip)
	if err1 != nil || err2 != nil {
		return flowEnds{}, false
	}
	f := flowEnds{proto: e.Protocol, la: la.Unmap(), ra: ra.Unmap(), lp: *lp}
	if rp != nil {
		f.rp = *rp
	}
	return f, true
}

func (x *ProcessIndex) serviceProc(proto string, port int, p Process) Process {
	if port > 0 && isInitProc(p.Comm) {
		if name, path := socketService(proto, port); name != "" {
			p.Comm, p.Path = name, path
		}
	}
	return p
}

func (x *ProcessIndex) rememberSock(s socketInfo, p Process, now time.Time) {
	if s.remote.Port() == 0 && s.remote.Addr().IsUnspecified() {
		x.remember(listenKey(s.proto, int(s.local.Port())), p, now)
		return
	}
	x.remember(sockKey(s), p, now)
	if p.Comm == "" && p.Path == "" {
		return
	}
	if x.peers == nil {
		x.peers = map[string]seenPeer{}
	}
	k := peerKey(s.proto, s.remote.Addr(), int(s.remote.Port()))
	until := now.Add(procRemember)
	old, ok := x.peers[k]
	if !ok || now.After(old.until) {
		x.peers[k] = seenPeer{p: p, until: until}
		return
	}
	old.until = until
	if old.p.Path != p.Path || old.p.Comm != p.Comm || old.p.Cgroup != p.Cgroup {
		old.mixed = true
	}
	x.peers[k] = old
}

func (x *ProcessIndex) remember(key string, p Process, now time.Time) {
	if key == "" || p.Comm == "" && p.Path == "" {
		return
	}
	if x.recent == nil {
		x.recent = map[string]seenProc{}
	}
	x.recent[key] = seenProc{p: p, until: now.Add(procRemember)}
}

func (x *ProcessIndex) prune(now time.Time) {
	x.pruned = now
	for k, s := range x.recent {
		if now.After(s.until) {
			delete(x.recent, k)
		}
	}
	for k, s := range x.peers {
		if now.After(s.until) {
			delete(x.peers, k)
		}
	}
}

func sockKey(s socketInfo) string {
	return flowKey(s.proto, int(s.local.Port()), s.remote.Addr(), int(s.remote.Port()))
}

// flowKey leaves out the local address: a socket bound to any address shows
// 0.0.0.0, the flow shows the address the packet left from.
func flowKey(proto string, lp int, remote netip.Addr, rp int) string {
	return proto + "|" + strconv.Itoa(lp) + "|" + remote.Unmap().String() + "|" + strconv.Itoa(rp)
}

func listenKey(proto string, port int) string {
	return "listen|" + proto + "|" + strconv.Itoa(port)
}

func peerKey(proto string, remote netip.Addr, port int) string {
	return "peer|" + proto + "|" + remote.Unmap().String() + "|" + strconv.Itoa(port)
}

func (x *ProcessIndex) procRoot() string {
	if x.Root == "" {
		return "/proc"
	}
	return x.Root
}

func readSockets(root, name string) []socketInfo {
	b, err := os.ReadFile(filepath.Join(root, "net", name))
	if err != nil {
		return nil
	}
	var out []socketInfo
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
		out = append(out, socketInfo{local, remote, strings.TrimSuffix(name, "6"), f[9], uid})
	}
	return out
}

func socketInode(fd string) (string, bool) {
	target, err := os.Readlink(fd)
	if err != nil || !strings.HasPrefix(target, "socket:[") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), true
}

func procInfo(base string, uid int) Process {
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
	return Process{strings.TrimSpace(string(comm)), path, group, &uid}
}

func (x *ProcessIndex) refresh() {
	root := x.procRoot()
	x.sockets = nil
	x.owners = map[string]Process{}
	x.icmpProc = Process{}
	x.unowned = nil
	x.at = time.Now()
	now := x.at
	if now.Sub(x.pruned) > 10*time.Second {
		x.prune(now)
	}
	wanted := map[string]socketInfo{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "icmp", "icmp6", "raw", "raw6"} {
		for _, s := range readSockets(root, name) {
			x.sockets = append(x.sockets, s)
			wanted[s.inode] = s
		}
	}
	udpPids := map[string]bool{}
	procs, _ := os.ReadDir(root)
	for _, ent := range procs {
		pid := ent.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		base := filepath.Join(root, pid)
		fds, err := os.ReadDir(filepath.Join(base, "fd"))
		if err != nil {
			continue
		}
		var inodes []string
		for _, fd := range fds {
			inode, ok := socketInode(filepath.Join(base, "fd", fd.Name()))
			if !ok {
				continue
			}
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
		info := procInfo(base, 0)
		for _, inode := range inodes {
			u := wanted[inode].uid
			p := info
			p.UID = &u
			x.owners[inode] = p
			if p.Comm == "ping" || p.Comm == "ping6" {
				x.icmpProc = p
			}
			if wanted[inode].proto == "udp" {
				udpPids[pid] = true
			}
		}
	}
	x.udpPids = udpPids
	for _, s := range x.sockets {
		p, ok := x.owners[s.inode]
		if !ok {
			continue
		}
		x.rememberSock(s, x.serviceProc(s.proto, int(s.local.Port()), p), now)
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
