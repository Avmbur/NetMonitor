package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"netmonitor/internal/ingest"
	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
)

// dropFeedKeep — сколько уже сброшенных строк ленты держать на один хост.
// Журнал отдаёт столько же, и отбор хоста выполняется до этого ограничения.
// Общий список на всех вытеснил бы редкий хост шумом соседнего.
const dropFeedKeep = 200

// dropBook — открытые hits DROP и оперативная лента.
// Открытые hits входят в отчёт и плитку, пока сброс их не записал.
// Лента сброс переживает: иначе журнал пустел бы каждые 15 минут.
// После перезапуска процесса лента пустая, отчёт читает уже записанные строки.
// Повтор того же event_id заменяет свой вклад, а не прибавляет его.
// Строка группы — тот же id, что сводка dp: и старые firewall_events.
// Причина, адрес и время остаются от первого события: ON CONFLICT их не меняет.
// Читатель берёт flushMu и только потом mu. Сброс держит flushMu и снимает
// открытые hits после успешной транзакции, до отпускания flushMu.
type dropBook struct {
	mu        sync.Mutex
	rows      map[string]*dropRow
	openProto map[string]string
}

type dropRow struct {
	diskID     string
	host       string
	at         int64
	ip         string
	reason     string
	hits       int
	proto      string
	dir        string
	localIP    string
	verdict    string
	localPort  sql.NullInt64
	remotePort sql.NullInt64
	contrib    map[string]int
	open       map[string]struct{}
}

type dropView struct {
	diskID     string
	host       string
	at         int64
	ip         string
	reason     string
	hits       int
	proto      string
	dir        string
	localIP    string
	verdict    string
	localPort  sql.NullInt64
	remotePort sql.NullInt64
}

type dropSum struct {
	IP     string
	Host   string
	Reason string
	Hits   int
}

type dropParsed struct {
	protoID    string
	diskID     string
	host       string
	at         int64
	ip         string
	reason     string
	hits       int
	proto      string
	dir        string
	localIP    string
	verdict    string
	localPort  sql.NullInt64
	remotePort sql.NullInt64
}

func dropReason(tag, verdict string) string {
	if tag != "" {
		return tag
	}
	if verdict != "" {
		return verdict
	}
	return "drop"
}

func dropShowIP(ip string) string {
	if ip == "" {
		return "—"
	}
	return ip
}

func dropKey(ip, host, reason string) string {
	return ip + "\x00" + host + "\x00" + reason
}

func portNull(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

func parseDrop(ag ingest.Agent, ev protocol.Event) (dropParsed, bool) {
	if ev.Kind != "firewall" || ev.EventID == "" {
		return dropParsed{}, false
	}
	var p protocol.FirewallPayload
	if json.Unmarshal(ev.Payload, &p) != nil {
		return dropParsed{}, false
	}
	hits := p.Hits
	if hits <= 0 {
		hits = 1
	}
	ip := ""
	if p.RemoteIP != "" {
		a, err := netipx.Parse(p.RemoteIP)
		if err != nil {
			return dropParsed{}, false
		}
		ip = netipx.Canonical(a)
	}
	local := ""
	if p.LocalIP != "" {
		a, err := netipx.Parse(p.LocalIP)
		if err != nil {
			return dropParsed{}, false
		}
		local = netipx.Canonical(a)
	}
	disk := ev.EventID
	if p.GroupID != "" {
		disk = ag.ID + "/" + p.GroupID
	}
	return dropParsed{
		protoID: ev.EventID, diskID: disk, host: ag.HostID, at: ev.ObservedAtMS,
		ip: ip, reason: dropReason(p.RuleTag, p.Verdict), hits: hits,
		proto: p.Protocol, dir: p.Direction, localIP: local, verdict: p.Verdict,
		localPort: portNull(p.LocalPort), remotePort: portNull(p.RemotePort),
	}, true
}

func (b *dropBook) missing(ids []string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	seen := map[string]struct{}{}
	var out []string
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if b.rows[id] == nil {
			out = append(out, id)
		}
	}
	return out
}

func (b *dropBook) add(facts []dropParsed, sticky map[string]dropParsed, flushed bool) {
	if len(facts) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rows == nil {
		b.rows = map[string]*dropRow{}
	}
	for _, f := range facts {
		row := b.rows[f.diskID]
		if row == nil {
			if st, ok := sticky[f.diskID]; ok {
				f.host = st.host
				f.at = st.at
				f.ip = st.ip
				f.reason = st.reason
				f.proto = st.proto
				f.dir = st.dir
				f.localIP = st.localIP
				f.verdict = st.verdict
				f.localPort = st.localPort
				f.remotePort = st.remotePort
			}
			row = &dropRow{
				diskID: f.diskID, host: f.host, at: f.at, ip: f.ip, reason: f.reason,
				hits: f.hits, proto: f.proto, dir: f.dir, localIP: f.localIP, verdict: f.verdict,
				localPort: f.localPort, remotePort: f.remotePort,
				contrib: map[string]int{f.protoID: f.hits},
			}
			if !flushed {
				row.open = map[string]struct{}{f.protoID: {}}
				if b.openProto == nil {
					b.openProto = map[string]string{}
				}
				b.openProto[f.protoID] = f.diskID
			}
			b.rows[f.diskID] = row
			continue
		}
		prev, seen := row.contrib[f.protoID]
		if seen {
			row.hits += f.hits - prev
		} else {
			row.hits += f.hits
		}
		row.contrib[f.protoID] = f.hits
		if !flushed {
			if row.open == nil {
				row.open = map[string]struct{}{}
			}
			row.open[f.protoID] = struct{}{}
			if b.openProto == nil {
				b.openProto = map[string]string{}
			}
			b.openProto[f.protoID] = row.diskID
		}
	}
	b.evictLocked()
}

func (b *dropBook) discardOpen(protoIDs []string) {
	if len(protoIDs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range protoIDs {
		diskID, ok := b.openProto[id]
		if !ok {
			continue
		}
		delete(b.openProto, id)
		row := b.rows[diskID]
		if row == nil {
			continue
		}
		if n, has := row.contrib[id]; has {
			row.hits -= n
			delete(row.contrib, id)
		}
		if row.open != nil {
			delete(row.open, id)
		}
		if len(row.contrib) == 0 || row.hits <= 0 {
			delete(b.rows, diskID)
		}
	}
	b.evictLocked()
}

func (b *dropBook) clearOpen(protoIDs []string) {
	if len(protoIDs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range protoIDs {
		diskID, ok := b.openProto[id]
		if !ok {
			continue
		}
		delete(b.openProto, id)
		row := b.rows[diskID]
		if row != nil && row.open != nil {
			delete(row.open, id)
		}
	}
	b.evictLocked()
}

func (b *dropBook) evictLocked() {
	type cand struct {
		id string
		at int64
	}
	by := map[string][]cand{}
	for id, row := range b.rows {
		if len(row.open) > 0 {
			continue
		}
		by[row.host] = append(by[row.host], cand{id: id, at: row.at})
	}
	for _, list := range by {
		if len(list) <= dropFeedKeep {
			continue
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].at != list[j].at {
				return list[i].at > list[j].at
			}
			return list[i].id < list[j].id
		})
		for _, c := range list[dropFeedKeep:] {
			delete(b.rows, c.id)
		}
	}
	for proto, diskID := range b.openProto {
		if b.rows[diskID] == nil {
			delete(b.openProto, proto)
		}
	}
}

func (b *dropBook) moveHost(from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, row := range b.rows {
		if row.host == from {
			row.host = to
		}
	}
}

func dropHostWanted(filter, host string) bool {
	return filter == "" || filter == "all" || filter == host
}

func (b *dropBook) pending(from, to int64, host string) []dropSum {
	b.mu.Lock()
	defer b.mu.Unlock()
	acc := map[string]*dropSum{}
	var order []string
	for _, row := range b.rows {
		if row.at < from || row.at > to || !dropHostWanted(host, row.host) {
			continue
		}
		n := 0
		for proto := range row.open {
			n += row.contrib[proto]
		}
		if n == 0 {
			continue
		}
		key := dropKey(row.ip, row.host, row.reason)
		g := acc[key]
		if g == nil {
			g = &dropSum{IP: row.ip, Host: row.host, Reason: row.reason}
			acc[key] = g
			order = append(order, key)
		}
		g.Hits += n
	}
	out := make([]dropSum, 0, len(order))
	for _, key := range order {
		out = append(out, *acc[key])
	}
	return out
}

func (b *dropBook) tile(since int64, host string, filtered bool, trusted map[string]struct{}) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, row := range b.rows {
		if row.at <= since {
			continue
		}
		if _, ok := trusted[row.host]; !ok {
			continue
		}
		if filtered && row.host != host {
			continue
		}
		for proto := range row.open {
			n += row.contrib[proto]
		}
	}
	return n
}

func (b *dropBook) views() []dropView {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []dropView
	for _, row := range b.rows {
		out = append(out, dropView{
			diskID: row.diskID, host: row.host, at: row.at, ip: row.ip, reason: row.reason,
			hits: row.hits, proto: row.proto, dir: row.dir, localIP: row.localIP, verdict: row.verdict,
			localPort: row.localPort, remotePort: row.remotePort,
		})
	}
	return out
}

func (s *Server) moveDropHost(from, to string) {
	s.drops.moveHost(from, to)
}

// noteImmediateFirewall пишет в ленту firewall, уже записанный этой транзакцией.
// В открытые hits его не кладёт: плитка сложила бы диск и память второй раз.
// Отложенное событие в этот момент ещё held, не ack, и в ленту его ставит rememberDrops.
func (s *Server) noteImmediateFirewall(jobs []*batchJob) {
	var facts []dropParsed
	for _, j := range jobs {
		if j == nil || j.err != nil {
			continue
		}
		staged := map[string]struct{}{}
		for _, it := range j.staged {
			staged[it.ev.EventID] = struct{}{}
		}
		acked := map[string]struct{}{}
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
			if _, ok := staged[ev.EventID]; ok {
				continue
			}
			f, ok := parseDrop(j.ag, ev)
			if !ok {
				continue
			}
			facts = append(facts, f)
		}
	}
	if len(facts) == 0 {
		return
	}
	s.drops.add(facts, nil, true)
}

func (s *Server) blockedNow(db *checkedRead, since int64, host string, filtered bool) int {
	{
		return s.blockedInMemory(db, since, host, filtered)
	}

}

// blockedInMemory — счётчик «блок» без записи на диск: удары из ленты памяти.
// После перезапуска монитора счёт начинается заново.
func (s *Server) blockedInMemory(db *checkedRead, since int64, host string, filtered bool) int {
	trusted := map[string]struct{}{}
	rows, err := db.Query(`SELECT host_id FROM agents WHERE trust_state='trusted'`)
	if err != nil {
		return 0
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			trusted[id] = struct{}{}
		}
	}
	rows.Close()
	n := 0
	for _, v := range s.drops.views() {
		if v.at <= since {
			continue
		}
		if _, ok := trusted[v.host]; !ok {
			continue
		}
		if filtered && v.host != host {
			continue
		}
		n += v.hits
	}
	return n
}

func (s *Server) readUIFirewall(db *checkedRead, filter string, filtered bool) []uiFlow {
	views := s.drops.views()
	trusted := map[string]struct{}{}
	rows, err := db.Query(`SELECT host_id FROM agents WHERE trust_state='trusted'`)
	if err != nil {
		return nil
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			trusted[id] = struct{}{}
		}
	}
	rows.Close()
	var kept []dropView
	hosts := map[string]struct{}{}
	var hostIDs []string
	for _, v := range views {
		if _, ok := trusted[v.host]; !ok {
			continue
		}
		if filtered && v.host != filter {
			continue
		}
		kept = append(kept, v)
		if _, ok := hosts[v.host]; !ok {
			hosts[v.host] = struct{}{}
			hostIDs = append(hostIDs, v.host)
		}
	}
	names := s.dropFeedNames(db, hostIDs)
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].at != kept[j].at {
			return kept[i].at > kept[j].at
		}
		return kept[i].diskID < kept[j].diskID
	})
	if len(kept) > dropFeedKeep {
		kept = kept[:dropFeedKeep]
	}
	var out []uiFlow
	for _, v := range kept {
		out = append(out, dropAsFlow(v, names[v.host]))
	}
	return out
}

func (s *Server) dropFeedNames(db *checkedRead, ids []string) map[string]string {
	out := map[string]string{}
	if len(ids) == 0 {
		return out
	}
	args := make([]any, len(ids))
	q := `SELECT host_id, COALESCE(hostname,'') FROM hosts WHERE host_id IN (`
	for i, id := range ids {
		if i > 0 {
			q += ","
		}
		q += "?"
		args[i] = id
		out[id] = ""
	}
	q += ")"
	rows, err := db.Query(q, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			out[id] = name
		}
	}
	return out
}

func dropAsFlow(v dropView, server string) uiFlow {
	f := uiFlow{
		FlowUID: v.diskID, When: liveWhen(v.at), HostID: v.host, Server: server,
		Protocol: v.proto, Direction: v.dir, Proc: "—", State: "block", Rule: "DROP",
	}
	f.Local = flowEndpoint(v.localIP, v.localPort)
	f.Remote = flowEndpoint(v.ip, v.remotePort)
	f.Peer = v.ip
	f.Addr = "→ " + f.Remote
	if f.Direction == "in" {
		port := "—"
		if v.localPort.Valid {
			port = ":" + strconv.FormatInt(v.localPort.Int64, 10)
		}
		f.Addr = port + " ← " + f.Remote
	}
	if v.verdict == "reject" {
		f.Rule = "REJECT"
	}
	f.Tip = fmt.Sprintf("%s; попыток: %d", f.Rule, v.hits)
	return f
}
