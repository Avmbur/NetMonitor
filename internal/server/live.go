package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"netmonitor/internal/ingest"
	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

// Live connections start empty and are rebuilt from the current agent stream.

type liveTable struct {
	mu        sync.Mutex
	loaded    bool
	instances map[string]string
	open      map[string]*liveFlow
	closed    map[string]struct{}
	// closedOld — прошлое поколение закрытых. Без записи на диск закрытые
	// держатся в памяти 15–30 минут и не копятся бесконечно.
	closedOld map[string]struct{}
	rotatedAt time.Time
}

// closedKeep — сколько поколение закрытых держит uid против запоздавшей пробы.
const closedKeep = 15 * time.Minute

func (t *liveTable) isClosedLocked(uid string) bool {
	if _, ok := t.closed[uid]; ok {
		return true
	}
	_, ok := t.closedOld[uid]
	return ok
}

func (t *liveTable) markClosedLocked(uid string) {
	if t.closed == nil {
		t.closed = map[string]struct{}{}
	}
	t.closed[uid] = struct{}{}
}

// rotateClosedLocked сдвигает поколения раз в closedKeep; force — для тестов.
func (t *liveTable) rotateClosedLocked(force bool) {
	now := time.Now()
	if t.rotatedAt.IsZero() {
		t.rotatedAt = now
	}
	if !force && now.Sub(t.rotatedAt) < closedKeep {
		return
	}
	t.closedOld = t.closed
	t.closed = map[string]struct{}{}
	t.rotatedAt = now
}

// liveSnapshot — стартовый набор. Без записи на диск снимок open_flows не
// обновляется, его строки стали бы вечными призраками: память начинает с пустого.
func (s *Server) liveSnapshot() (map[string]*liveFlow, error) {
	{
		return map[string]*liveFlow{}, nil
	}

}

type liveFlow struct {
	uid, agentID, hostID, bootID               string
	seq                                        int64
	direction, protocol                        string
	localIP, remoteIP, replySrc                string
	origin                                     string
	localPort, remotePort                      *int
	procComm, procPath, procCgroup             string
	procUID                                    *int
	container, dns, state                      string
	origBytes, replyBytes, firstSeen, lastSeen int64
	incomplete, replySeen                      int
	rateT1, rateBytes, rateDur                 int64
	rateKnown                                  bool
}

type liveRate struct {
	t1, bytes, dur int64
	known          bool
}

type liveAgent struct {
	trust string
	boot  sql.NullString
}

type liveHost struct {
	name string
	last int64
}

func (s *Server) ensureLive() error {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if s.live.loaded {
		return nil
	}
	snap, err := s.liveSnapshot()
	if err != nil {
		return err
	}
	s.live.install(snap)
	return nil
}

// moveLiveHost — продолжение истории без диска: соединения агента в памяти
// переходят на прежний host_id, как строки flows при записи на диск.
func (s *Server) moveLiveHost(from, to string) {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	for _, f := range s.live.open {
		if f.hostID == from {
			f.hostID = to
		}
	}
}

func (t *liveTable) install(open map[string]*liveFlow) {
	if open == nil {
		open = map[string]*liveFlow{}
	}
	t.open = open
	t.closed = map[string]struct{}{}
	t.closedOld = nil
	t.loaded = true
}

func (s *Server) liveAfterCommit(jobs []*batchJob) {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if !s.live.loaded {
		snap, err := s.liveSnapshot()
		if err != nil {
			log.Printf("живое состояние: %v", err)
			return
		}
		s.live.install(snap)
		// Снимок уже содержит срочные строки. Отложенные ещё не в базе.

	}
	{
		s.live.rotateClosedLocked(false)
	}
	s.liveApplyLocked(jobs)
}

func (s *Server) liveActivity(host string, filtered, withRows bool) (int, []flowRow, map[string]liveRate, error) {
	if err := s.ensureLive(); err != nil {
		return 0, nil, nil, err
	}
	agents, hosts, err := readLiveMeta(s.st.DB)
	if err != nil {
		return 0, nil, nil, err
	}
	s.pulseMu.Lock()
	for id, h := range hosts {
		if s.hostSeen[id] > h.last {
			h.last = s.hostSeen[id]
			hosts[id] = h
		}
	}
	s.pulseMu.Unlock()
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	var drop []string
	var list []*liveFlow
	recent := store.NowMS() - 120000
	for uid, f := range s.live.open {
		ag, ok := agents[f.agentID]
		if !ok || ag.boot.Valid && ag.boot.String != f.bootID {
			// После перезагрузки сервера соединения нового boot могут обогнать
			// пульс с этим boot. Свежие ждут его, а не выбрасываются насовсем.
			if ok && f.lastSeen > recent {
				continue
			}
			drop = append(drop, uid)
			continue
		}
		if ag.trust != "trusted" {
			continue
		}
		if filtered && f.hostID != host {
			continue
		}
		list = append(list, f)
	}
	for _, uid := range drop {
		delete(s.live.open, uid)
		s.live.markClosedLocked(uid)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].lastSeen != list[j].lastSeen {
			return list[i].lastSeen > list[j].lastSeen
		}
		return list[i].uid < list[j].uid
	})
	n := len(list)
	if !withRows {
		return n, nil, nil, nil
	}
	rows := make([]flowRow, 0, n)
	rates := map[string]liveRate{}
	for _, f := range list {
		rows = append(rows, f.row(hosts[f.hostID]))
		if f.rateKnown {
			rates[f.uid] = liveRate{t1: f.rateT1, bytes: f.rateBytes, dur: f.rateDur, known: true}
		}
	}
	return n, rows, rates, nil
}

func (s *Server) liveApplyLocked(jobs []*batchJob) {
	for _, j := range jobs {
		if j == nil || j.err != nil {
			continue
		}
		stagedID := make(map[string]struct{}, len(j.staged))
		for _, it := range j.staged {
			stagedID[it.ev.EventID] = struct{}{}
		}
		acked := make(map[string]struct{}, len(j.res.Ack))
		for _, id := range j.res.Ack {
			acked[id] = struct{}{}
		}
		events := j.batch.Events
		{
			events = j.applied
		}
		for _, ev := range events {
			if _, ok := acked[ev.EventID]; !ok {
				continue
			}
			if _, later := stagedID[ev.EventID]; later {
				continue
			}
			switch ev.Kind {
			case "flow":
				s.liveApplyFlowLocked(j.ag, ev, false)
			case "sample":
				s.liveApplySampleLocked(j.ag, ev, false)
			}
		}
		for _, it := range j.staged {
			switch it.ev.Kind {
			case "flow":
				s.liveApplyFlowLocked(it.ag, it.ev, true)
			case "sample":
				s.liveApplySampleLocked(it.ag, it.ev, true)
			}
		}
	}
}

func (s *Server) closedUIDLocked(agentID, uid string) string {
	{
		return agentID + "/" + s.live.instances[agentID] + "/" + uid
	}

}

func (s *Server) liveApplyFlowLocked(ag ingest.Agent, ev protocol.Event, staged bool) {
	var p protocol.FlowPayload
	if json.Unmarshal(ev.Payload, &p) != nil || p.FlowUID == "" {
		return
	}
	if s.live.isClosedLocked(s.closedUIDLocked(ag.ID, p.FlowUID)) {
		return
	}
	if f := s.live.open[p.FlowUID]; f != nil {
		if f.hostID != ag.HostID {
			return
		}
		if f.agentID != ag.ID {
			f.agentID = ag.ID
		}
		if ev.Seq <= f.seq {
			return
		}
		if p.EndedAtMS != nil {
			delete(s.live.open, p.FlowUID)
			s.live.markClosedLocked(s.closedUIDLocked(ag.ID, p.FlowUID))
			return
		}
		mergeLiveFlow(f, p, ev.Seq)
		return
	}
	if p.EndedAtMS != nil {
		s.live.markClosedLocked(s.closedUIDLocked(ag.ID, p.FlowUID))
		return
	}
	s.live.open[p.FlowUID] = newLiveFlow(ag, p, ev.Seq)
}

func (s *Server) liveApplySampleLocked(ag ingest.Agent, ev protocol.Event, staged bool) {
	var p protocol.SamplePayload
	if json.Unmarshal(ev.Payload, &p) != nil {
		return
	}
	if p.Flow != nil {
		raw, err := json.Marshal(p.Flow)
		if err != nil {
			return
		}
		s.liveApplyFlowLocked(ag, protocol.Event{EventID: ev.EventID, Seq: ev.Seq, Kind: "flow", ObservedAtMS: ev.ObservedAtMS, Payload: raw}, staged)
		if p.FlowUID == "" {
			p.FlowUID = p.Flow.FlowUID
		}
		if p.Direction == "" {
			p.Direction = p.Flow.Direction
		}
	}
	f := s.live.open[p.FlowUID]
	if f == nil || f.hostID != ag.HostID {
		return
	}
	if f.agentID != ag.ID {
		f.agentID = ag.ID
	}
	noteLiveRate(f, p)
}

func newLiveFlow(ag ingest.Agent, p protocol.FlowPayload, seq int64) *liveFlow {
	origin := p.Origin
	if origin == "" {
		origin = "host"
	}
	boot := p.BootID
	if boot == "" {
		boot = "unknown"
	}
	if origin == "docker" && p.Direction != "bridge" {
		p.ProcComm, p.ProcPath, p.ProcCgroup, p.ProcUID = "", "", "", nil
	}
	first := p.FirstSeenMS
	if first <= 0 {
		first = p.LastSeenMS
	}
	return &liveFlow{
		uid: p.FlowUID, agentID: ag.ID, hostID: ag.HostID, bootID: boot, seq: seq,
		direction: p.Direction, protocol: strings.ToLower(p.Protocol),
		localIP: canonIP(p.LocalIP), remoteIP: canonIP(p.RemoteIP), replySrc: canonIP(p.ReplySrcIP),
		origin: origin, localPort: cloneInt(p.LocalPort), remotePort: cloneInt(p.RemotePort),
		procComm: p.ProcComm, procPath: p.ProcPath, procCgroup: p.ProcCgroup, procUID: cloneInt(p.ProcUID),
		container: p.Container, dns: p.DNSName, state: p.State,
		origBytes: int64Or0(p.OrigBytes), replyBytes: int64Or0(p.ReplyBytes), firstSeen: first, lastSeen: p.LastSeenMS,
		incomplete: p.Incomplete, replySeen: p.ReplySeen,
	}
}

func mergeLiveFlow(f *liveFlow, p protocol.FlowPayload, seq int64) {
	origin := p.Origin
	if origin == "" {
		origin = "host"
	}
	docker := origin == "docker" && p.Direction != "bridge"
	if p.LastSeenMS > f.lastSeen {
		f.lastSeen = p.LastSeenMS
	}
	if p.FirstSeenMS > 0 && (f.firstSeen <= 0 || p.FirstSeenMS < f.firstSeen) {
		f.firstSeen = p.FirstSeenMS
	}
	if p.State != "" {
		f.state = p.State
	}
	if p.ReplySeen > f.replySeen {
		f.replySeen = p.ReplySeen
	}
	f.origBytes = int64Or0(p.OrigBytes)
	f.replyBytes = int64Or0(p.ReplyBytes)
	f.direction = p.Direction
	f.origin = origin
	f.localIP = canonIP(p.LocalIP)
	f.remoteIP = canonIP(p.RemoteIP)
	f.localPort = cloneInt(p.LocalPort)
	f.remotePort = cloneInt(p.RemotePort)
	if p.ReplySrcIP != "" {
		f.replySrc = canonIP(p.ReplySrcIP)
	}
	if docker {
		f.procComm, f.procPath, f.procCgroup, f.procUID = "", "", "", nil
	} else {
		if p.ProcComm != "" {
			f.procComm = p.ProcComm
		}
		if p.ProcPath != "" {
			f.procPath = p.ProcPath
		}
		if p.ProcCgroup != "" {
			f.procCgroup = p.ProcCgroup
		}
		if p.ProcUID != nil {
			f.procUID = cloneInt(p.ProcUID)
		}
	}
	if p.Container != "" {
		f.container = p.Container
	}
	if p.DNSName != "" {
		f.dns = p.DNSName
	}
	if p.Incomplete > f.incomplete {
		f.incomplete = p.Incomplete
	}
	f.seq = seq
}

func noteLiveRate(f *liveFlow, p protocol.SamplePayload) {
	if p.Quality == "" {
		p.Quality = "ok"
	}
	type piece struct{ t0, t1, n int64 }
	var parts []piece
	if p.Incomplete == 1 || p.Quality == "counter_reset" {
		parts = []piece{{p.T0MS, p.T1MS, p.OrigBytesDelta + p.ReplyBytesDelta}}
	} else {
		dur := p.T1MS - p.T0MS
		if dur <= 0 {
			dur = 1
		}
		t := p.T0MS
		remainO, remainR := p.OrigBytesDelta, p.ReplyBytesDelta
		for t < p.T1MS {
			next := (t/60000 + 1) * 60000
			if next > p.T1MS {
				next = p.T1MS
			}
			slice := next - t
			var o, r int64
			if next == p.T1MS {
				o, r = remainO, remainR
			} else {
				o = p.OrigBytesDelta * slice / dur
				r = p.ReplyBytesDelta * slice / dur
				remainO -= o
				remainR -= r
			}
			parts = append(parts, piece{t, next, o + r})
			t = next
		}
	}
	for _, part := range parts {
		if part.t1 < f.rateT1 {
			continue
		}
		f.rateT1 = part.t1
		if d := part.t1 - part.t0; d > 0 {
			f.rateBytes = part.n
			f.rateDur = d
			f.rateKnown = true
		}
	}
}

func stampLiveRates(flows []uiFlow, rates map[string]liveRate) {
	if len(flows) == 0 || len(rates) == 0 {
		return
	}
	now := store.NowMS()
	for i := range flows {
		r, ok := rates[flows[i].FlowUID]
		if !ok || !r.known || r.dur <= 0 || r.t1 <= now-30000 {
			continue
		}
		flows[i].Rate = r.bytes * 1000 / r.dur
		flows[i].RateKnown = true
	}
}

func (f *liveFlow) row(h liveHost) flowRow {
	var r flowRow
	r.f.FlowUID = f.uid
	r.f.When = liveWhen(f.lastSeen)
	r.f.HostID = f.hostID
	r.f.Server = h.name
	r.f.Direction = f.direction
	r.f.Protocol = f.protocol
	r.f.Proc = f.procComm
	r.f.Path = f.procPath
	r.f.Container = f.container
	r.f.Incomplete = f.incomplete != 0
	r.lip = f.localIP
	r.rip = f.remoteIP
	r.lp = nullInt(f.localPort)
	r.rp = nullInt(f.remotePort)
	r.puid = nullInt(f.procUID)
	r.cg = f.procCgroup
	r.flowDNS = f.dns
	r.ob = f.origBytes
	r.rb = f.replyBytes
	r.state = f.state
	r.reply = f.replySeen
	r.last = h.last
	r.origin = f.origin
	r.replySrc = f.replySrc
	return r
}

func readLiveMeta(db *sql.DB) (map[string]liveAgent, map[string]liveHost, error) {
	agents := map[string]liveAgent{}
	rows, err := db.Query(`SELECT agent_id, trust_state, boot_id FROM agents`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var id string
		var ag liveAgent
		if rows.Scan(&id, &ag.trust, &ag.boot) != nil {
			continue
		}
		agents[id] = ag
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	hosts := map[string]liveHost{}
	rows, err = db.Query(`SELECT host_id, COALESCE(hostname,''), COALESCE(last_seen_ms,0) FROM hosts`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var h liveHost
		if rows.Scan(&id, &h.name, &h.last) != nil {
			continue
		}
		hosts[id] = h
	}
	return agents, hosts, rows.Err()
}

func canonIP(s string) string {
	if s == "" {
		return ""
	}
	a, err := netipx.Parse(s)
	if err != nil {
		return s
	}
	return netipx.Canonical(a)
}

func cloneInt(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func int64Or0(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func nullInt(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

func liveWhen(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.Unix(ms/1000, 0).In(time.Local).Format("2006-01-02 15:04:05")
}
