package collect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/outbox"
	"netmonitor/internal/protocol"
)

type DumpOpts struct {
	HostID, BootID, Namespace string
	Local                     []netip.Addr
	LAN, Overlay, Own         []netip.Prefix
	DockerNets                []netip.Prefix
	SkipIfaces                map[string]bool
	AddrIface                 map[string]string
	Monitor                   netip.Addr
	MonitorPort               int
	NowMS, MonoMS             int64
	ObserveDocker             bool
	// Snapshot began before its netlink request. Newer events cannot be closed by it.
	SnapshotMono int64
	Process      func(Entry) Process
	Container    func(string) string
}
type checkpoint struct {
	Flow           protocol.FlowPayload
	Entry          Entry
	MonoMS, WallMS int64
	SeenMono       int64
}

func entryKey(e Entry, opt DumpOpts) string {
	ns := opt.Namespace
	if ns == "" {
		ns = "1"
	}
	e.Namespace = ns
	return opt.BootID + "/" + ns + "/" + e.TupleKey()
}
func loadCheckpoint(tx *sql.Tx, key string) (checkpoint, bool, error) {
	var c checkpoint
	var raw string
	err := tx.QueryRow("SELECT payload FROM checkpoints WHERE flow_key=?", key).Scan(&raw)
	if err == sql.ErrNoRows {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	err = json.Unmarshal([]byte(raw), &c)
	return c, true, err
}
func saveCheckpoint(tx *sql.Tx, key string, c checkpoint) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO checkpoints(flow_key,payload) VALUES(?,?) ON CONFLICT(flow_key) DO UPDATE SET payload=excluded.payload", key, string(b))
	return e
}
func ApplyEvent(tx *sql.Tx, e Entry, kind string, opt DumpOpts) error {
	if Skip(e, opt.Monitor, opt.MonitorPort) {
		return nil
	}
	return observe(tx, e, kind, opt)
}
func ApplyDump(tx *sql.Tx, entries []Entry, opt DumpOpts) error {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if Skip(e, opt.Monitor, opt.MonitorPort) {
			continue
		}
		key := entryKey(e, opt)
		seen[key] = true
		if err := observe(tx, e, "dump", opt); err != nil {
			return err
		}
	}
	rows, err := tx.Query("SELECT flow_key,payload FROM checkpoints")
	if err != nil {
		return err
	}
	type missing struct {
		key string
		c   checkpoint
	}
	var gone []missing
	for rows.Next() {
		var key, raw string
		if err = rows.Scan(&key, &raw); err != nil {
			rows.Close()
			return err
		}
		if seen[key] {
			continue
		}
		var c checkpoint
		if err = json.Unmarshal([]byte(raw), &c); err != nil {
			rows.Close()
			return err
		}
		// A checkpoint from another boot is historical, not evidence of an application close.
		if c.Flow.EndedAtMS != nil || c.Flow.BootID != opt.BootID {
			continue
		}
		if opt.SnapshotMono > 0 && c.SeenMono > opt.SnapshotMono {
			continue
		}
		gone = append(gone, missing{key, c})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, g := range gone {
		if err = closeCheckpoint(tx, g.key, g.c, opt, "unknown"); err != nil {
			return err
		}
	}
	_, err = tx.Exec("DELETE FROM checkpoints WHERE (json_extract(payload,'$.Flow.ended_at_ms') IS NOT NULL AND json_extract(payload,'$.SeenMono')<?) OR json_extract(payload,'$.Flow.boot_id')<>?", opt.MonoMS-600000, opt.BootID)
	return err
}
func sameInstance(c checkpoint, e Entry) bool {
	if c.Entry.CTID != nil && e.CTID != nil && *c.Entry.CTID != *e.CTID {
		return false
	}
	if c.Entry.StartNS > 0 && e.StartNS > 0 && c.Entry.StartNS != e.StartNS {
		return false
	}
	return true
}
func observe(tx *sql.Tx, e Entry, kind string, opt DumpOpts) error {
	e.Namespace = opt.Namespace
	key := entryKey(e, opt)
	prev, exists, err := loadCheckpoint(tx, key)
	if err != nil {
		return err
	}
	if exists && prev.Flow.EndedAtMS != nil {
		if sameInstance(prev, e) && (kind != "new" || e.StartNS > 0 && prev.Entry.StartNS == e.StartNS) {
			return nil
		}
		exists = false
	}
	if exists && !sameInstance(prev, e) {
		// A late DESTROY must never close a replacement using the same tuple.
		if kind == "destroy" {
			return nil
		}
		if err = closeCheckpoint(tx, key, prev, opt, "unknown"); err != nil {
			return err
		}
		exists = false
	}
	if exists && kind == "dump" && opt.SnapshotMono > 0 && prev.SeenMono > opt.SnapshotMono {
		return nil
	}
	if exists && opt.MonoMS < prev.SeenMono {
		return nil
	}
	fp := makeFlow(e, opt)
	if opt.drop(e, fp) {
		return nil
	}
	if exists {
		fp.FlowUID = prev.Flow.FlowUID
		fp.FirstSeenMS = prev.Flow.FirstSeenMS
		fp.StartedAtMS = prev.Flow.StartedAtMS
		if fp.StartedAtMS == nil && e.StartNS > 0 {
			n := e.StartNS / 1_000_000
			fp.StartedAtMS = &n
		}
		if e.StartNS == 0 {
			e.StartNS = prev.Entry.StartNS
		}
		if e.CTID == nil {
			e.CTID = prev.Entry.CTID
		}
		fp.Incomplete = prev.Flow.Incomplete
		fp.ProcComm = prev.Flow.ProcComm
		fp.ProcPath = prev.Flow.ProcPath
		fp.ProcUID = prev.Flow.ProcUID
		fp.ProcCgroup = prev.Flow.ProcCgroup
		if fp.LastSeenMS < fp.FirstSeenMS {
			fp.LastSeenMS = fp.FirstSeenMS
		}
		if !e.CountersKnown {
			fp.OrigBytes = prev.Flow.OrigBytes
			fp.ReplyBytes = prev.Flow.ReplyBytes
			fp.OrigPackets = prev.Flow.OrigPackets
			fp.ReplyPackets = prev.Flow.ReplyPackets
		}
		fp.ReplySeen = max(fp.ReplySeen, prev.Flow.ReplySeen)
	} else {
		start := e.StartNS
		// A NEW event is the birth of the flow. Some kernels leave CTA_TIMESTAMP
		// out of the event even with nf_conntrack_timestamp on, and the identity
		// is still exact: this conntrack id, seen starting now.
		if start == 0 && kind == "new" && e.CTID != nil {
			start = opt.NowMS * 1_000_000
		}
		fp.FlowUID = flowUID(opt.HostID, opt.BootID, e, start)
		if start == 0 || e.CTID == nil {
			fp.FlowUID += "/" + idgen.NewV7()
		}
		if kind != "new" || start == 0 || e.CTID == nil {
			fp.Incomplete = 1
		}
		if start > 0 {
			ms := start / 1_000_000
			fp.StartedAtMS = &ms
		}
	}
	if opt.containerSide(fp, e) {
		// Clear process data saved before Docker attribution was available.
		fp.ProcComm, fp.ProcPath, fp.ProcCgroup, fp.ProcUID = "", "", "", nil
	}
	if (fp.ProcComm == "" || fp.ProcPath == "") && opt.Process != nil && !opt.containerSide(fp, e) {
		p := opt.Process(e)
		fp.ProcComm = p.Comm
		fp.ProcPath = p.Path
		fp.ProcUID = p.UID
		fp.ProcCgroup = p.Cgroup
	}
	if kind == "destroy" {
		now := max(opt.NowMS, fp.FirstSeenMS)
		fp.EndedAtMS = &now
		fp.CloseReason = closeReason(e.State)
	}
	pri := 1
	if !exists || kind == "destroy" || fp.ReplySeen > prev.Flow.ReplySeen || e.State != prev.Entry.State {
		pri = 5
	}
	procNew := exists && ((prev.Flow.ProcComm == "" && fp.ProcComm != "") || (prev.Flow.ProcPath == "" && fp.ProcPath != ""))
	metadataChanged := exists && (fp.Container != prev.Flow.Container || fp.Origin != prev.Flow.Origin ||
		fp.Direction != prev.Flow.Direction || fp.LocalIP != prev.Flow.LocalIP || fp.RemoteIP != prev.Flow.RemoteIP ||
		fp.ProcComm != prev.Flow.ProcComm || fp.ProcPath != prev.Flow.ProcPath || fp.ProcCgroup != prev.Flow.ProcCgroup)
	sendFlow := !exists || kind != "dump" || pri == 5 || procNew || metadataChanged
	if sendFlow {
		if err = enqueue(tx, "flow", pri, fp, opt.NowMS); err != nil {
			return err
		}
	}
	if exists && e.CountersKnown && prev.Entry.CountersKnown && opt.MonoMS >= prev.MonoMS {
		dt := max(int64(1), opt.MonoMS-prev.MonoMS)
		ds := []int64{e.OrigBytes - prev.Entry.OrigBytes, e.ReplyBytes - prev.Entry.ReplyBytes, e.OrigPackets - prev.Entry.OrigPackets, e.ReplyPackets - prev.Entry.ReplyPackets}
		quality := "ok"
		// Above 1 Tbit/s (L3) is a reset/corrupt counter on this collector; never graph it.
		for i, d := range ds {
			if d < 0 || i < 2 && d/dt > 125_000_000 {
				quality = "counter_reset"
			}
		}
		wallDelta := opt.NowMS - prev.WallMS
		if abs(wallDelta-dt) > 2000 {
			if err = enqueue(tx, "health", 10, protocol.HealthPayload{Kind: "clock_jump", Note: fmt.Sprintf("wall=%d monotonic=%d", wallDelta, dt)}, opt.NowMS); err != nil {
				return err
			}
		}
		if quality == "counter_reset" {
			ds = []int64{0, 0, 0, 0}
			fp.Incomplete = 1
		}
		// Anchor the monotonic duration at observation UTC, not at old wall time.
		sp := protocol.SamplePayload{FlowUID: fp.FlowUID, T0MS: opt.NowMS - dt, T1MS: opt.NowMS,
			OrigBytesDelta: ds[0], ReplyBytesDelta: ds[1], OrigPacketsDelta: ds[2], ReplyPacketsDelta: ds[3],
			Quality: quality, Direction: fp.Direction, RemoteScope: fp.RemoteScope, Flow: &fp}
		if quality != "ok" {
			sp.Incomplete = 1
		}
		if ds[0]+ds[1]+ds[2]+ds[3] > 0 || quality != "ok" {
			if err = enqueue(tx, "sample", 0, sp, opt.NowMS); err != nil {
				return err
			}
		}
	}

	// Events with no counters do not erase a valid counter baseline.
	mono, wall := opt.MonoMS, opt.NowMS
	if exists && !e.CountersKnown {
		e.OrigBytes = prev.Entry.OrigBytes
		e.ReplyBytes = prev.Entry.ReplyBytes
		e.OrigPackets = prev.Entry.OrigPackets
		e.ReplyPackets = prev.Entry.ReplyPackets
		e.CountersKnown = prev.Entry.CountersKnown
		mono = prev.MonoMS
		wall = prev.WallMS
	}
	// A witnessed NEW starts a zero baseline even when the kernel omits
	// counters from that notification. A first dump keeps its observed baseline.
	if !exists && kind == "new" {
		e.CountersKnown = true
		e.OrigBytes = 0
		e.ReplyBytes = 0
		e.OrigPackets = 0
		e.ReplyPackets = 0
	}
	return saveCheckpoint(tx, key, checkpoint{Flow: fp, Entry: e, MonoMS: mono, WallMS: wall, SeenMono: opt.MonoMS})
}
func closeCheckpoint(tx *sql.Tx, key string, c checkpoint, opt DumpOpts, reason string) error {
	if c.Flow.EndedAtMS != nil {
		return nil
	}
	end := max(opt.NowMS, c.Flow.FirstSeenMS)
	c.Flow.EndedAtMS = &end
	c.Flow.LastSeenMS = end
	c.Flow.CloseReason = reason
	if err := enqueue(tx, "flow", 5, c.Flow, opt.NowMS); err != nil {
		return err
	}
	c.SeenMono = opt.MonoMS
	return saveCheckpoint(tx, key, c)
}
func makeFlow(e Entry, opt DumpOpts) protocol.FlowPayload {
	dir, lip, rip, lp, rp := ClassifyNets(e, opt.Local, opt.DockerNets)
	remote, _ := netipx.Parse(rip)
	p := protocol.FlowPayload{BootID: opt.BootID, CtID: e.CTID, FirstSeenMS: opt.NowMS, LastSeenMS: opt.NowMS,
		IPVersion: e.IPVersion, Protocol: e.Protocol, OrigSrcIP: ipStr(e.OrigSrc), OrigDstIP: ipStr(e.OrigDst),
		OrigSrcPort: e.OrigSport, OrigDstPort: e.OrigDport, ReplySrcIP: ipStr(e.ReplySrc), ReplyDstIP: ipStr(e.ReplyDst),
		Direction: dir, LocalIP: lip, RemoteIP: rip, LocalPort: lp, RemotePort: rp,
		RemoteScope: netipx.Scope(remote, orLAN(opt.LAN), opt.Overlay, opt.Own),
		Origin:      opt.origin(lip, e), State: e.State, ICMPType: e.ICMPType, ICMPCode: e.ICMPCode, Zone: strconv.Itoa(e.Zone), NS: opt.Namespace}
	if opt.containerSide(p, e) {
		p.Origin = "docker"
	}
	if opt.Container != nil {
		p.Container = opt.Container(lip)
		if p.Container == "" {
			p.Container = opt.Container(ipStr(e.ReplySrc))
		}
	}
	if !e.Unreplied && (e.Assured || e.ReplyBytes > 0 || e.ReplyPackets > 0 || e.State == "ESTABLISHED") {
		p.ReplySeen = 1
	}
	if e.CountersKnown {
		p.OrigBytes = &e.OrigBytes
		p.ReplyBytes = &e.ReplyBytes
		p.OrigPackets = &e.OrigPackets
		p.ReplyPackets = &e.ReplyPackets
	}
	return p
}

func orLAN(lan []netip.Prefix) []netip.Prefix {
	if len(lan) == 0 {
		return netipx.DefaultLAN()
	}
	return lan
}

// containerSide: соединение контейнера с внешним миром. Процесса хоста у него нет;
// на опубликованном порту поиск по порту нашёл бы docker-proxy, а правила по
// процессу в forward не действуют.
func (opt DumpOpts) containerSide(fp protocol.FlowPayload, e Entry) bool {
	if fp.Direction == "bridge" {
		return false
	}
	ip, err := netip.ParseAddr(fp.LocalIP)
	return err == nil && prefixContains(ip, opt.DockerNets) || prefixContains(e.ReplySrc, opt.DockerNets)
}

func (opt DumpOpts) origin(localIP string, e Entry) string {
	if ip, err := netip.ParseAddr(localIP); err == nil && prefixContains(ip, opt.DockerNets) {
		return "docker"
	}
	iface := opt.AddrIface[localIP]
	if dockerIface(iface) {
		return "docker"
	}
	if opt.Process != nil {
		p := opt.Process(e)
		if dockerCgroup(p.Cgroup) && dockerIface(iface) {
			return "docker"
		}
	}
	return "host"
}

func (opt DumpOpts) drop(e Entry, fp protocol.FlowPayload) bool {
	if Skip(e, opt.Monitor, opt.MonitorPort) {
		return true
	}
	if len(opt.SkipIfaces) > 0 {
		if iface := opt.AddrIface[fp.LocalIP]; iface != "" && opt.SkipIfaces[iface] {
			return true
		}
	}
	if opt.ObserveDocker || fp.Origin != "docker" {
		return false
	}
	remote, err := netipx.Parse(fp.RemoteIP)
	if err != nil {
		return false
	}
	for _, p := range opt.DockerNets {
		if p.Contains(remote) {
			return true
		}
	}
	return false
}

func dockerIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"docker", "br-", "veth", "cni", "flannel", "calico", "podman", "cni0", "lxc"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return n == "docker0" || n == "podman0"
}

func dockerCgroup(cg string) bool {
	c := strings.ToLower(cg)
	return strings.Contains(c, "docker") || strings.Contains(c, "libpod") || strings.Contains(c, "containerd") || strings.Contains(c, "lxc")
}

func closeReason(state string) string {
	switch state {
	case "TIME_WAIT", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK":
		return "fin"
	case "CLOSE":
		return "unknown"
	}
	return "unknown"
}
func flowUID(host, boot string, e Entry, start int64) string {
	ct := "unknown"
	if e.CTID != nil {
		ct = strconv.FormatInt(*e.CTID, 10)
	}
	ns := e.Namespace
	if ns == "" {
		ns = "1"
	}
	return host + "/" + boot + "/" + ns + "/" + strconv.Itoa(e.Zone) + "/" + ct + "/" + strconv.FormatInt(start, 10)
}
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
func enqueue(tx *sql.Tx, kind string, pri int, p any, now int64) error {
	return outbox.Insert(tx, kind, pri, p, now)
}
