package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/ingest"
	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

// applyServiceBatch принимает телеметрию в память и квитирует её сразу.
// На диск попадают вопрос (один раз), бан и смена версии или портов SSH.
func (s *Server) applyServiceBatch(tx *sql.Tx, job *batchJob) (ingest.Result, error) {
	var res ingest.Result
	var staged []stagedEvent
	var coverHost, coverAll bool
	ag := job.ag
	stream := s.streams[ag.ID]
	if job.batch.Instance == "" || stream == nil || stream.instance != job.batch.Instance {
		res.Err = "agent instance: poll required"
		return res, nil
	}
events:
	for _, ev := range job.batch.Events {
		if ev.EventID == "" || ev.Kind == "" || ev.Seq <= 0 || ev.ObservedAtMS <= 0 {
			res.Err = "event_id, kind, positive seq and observed_at_ms are required"
			break
		}
		if err := ingest.ValidatePayload(ev); err != nil {
			res.Err = fmt.Sprintf("%s: %v", ev.EventID, err)
			break
		}
		if telemetryKind(ev.Kind) && ev.Seq <= job.serviceSeq {
			res.Ack = append(res.Ack, ev.EventID)
			continue
		}
		// Observations older than the closed-UID retention are not current state.
		if (ev.Kind == "flow" || ev.Kind == "sample") && job.now-ev.ObservedAtMS >= closedKeep.Milliseconds() {
			res.Ack = append(res.Ack, ev.EventID)
			job.serviceSeq = max(job.serviceSeq, ev.Seq)
			continue
		}
		switch ev.Kind {
		case "flow", "sample":
			staged = append(staged, stagedEvent{ag: ag, ev: ev, received: job.now})
			res.Ack = append(res.Ack, ev.EventID)
		case "firewall":
			// Не staged: после коммита noteImmediateFirewall кладёт удар в ленту журнала.
			res.Ack = append(res.Ack, ev.EventID)
		case "dns":
			// На диск — только новая пара имени из правил и групп: по ней растёт политика.
			// Закрытие вопросов — один раз на пачку, и только если пара действительно новая.
			if ag.Trust == "trusted" {
				added, err := noteRuleDNS(tx, ag, ev)
				if err != nil {
					return res, err
				}
				if added {
					// dns_seen общий для всех серверов, пара второй раз не придёт.
					coverAll = true
				}
			}
			res.Ack = append(res.Ack, ev.EventID)
		case "health":
			bad, err := s.noteHealth(tx, ag, ev, job.now)
			if err != nil {
				return res, err
			}
			if bad != "" {
				res.Err = fmt.Sprintf("%s: %s", ev.EventID, bad)
				break events
			}
			if ag.Trust == "trusted" {
				// firewall_restored остаётся в журнале действий.
				if err := s.autoban(tx, ag, ev, job.now); err != nil {
					return res, err
				}
			}
			res.Ack = append(res.Ack, ev.EventID)
		case "ssh":
			if err := s.noteSSH(job, ag, ev); err != nil {
				return res, err
			}
			if err := s.persistSSHBrute(tx, ag.HostID, ev, job.now, job); err != nil {
				return res, err
			}
			if ag.Trust == "trusted" {
				if err := s.autoban(tx, ag, ev, job.now); err != nil {
					return res, err
				}
			}
			res.Ack = append(res.Ack, ev.EventID)
		case "scan":
			if ag.Trust == "trusted" {
				if err := s.autoban(tx, ag, ev, job.now); err != nil {
					return res, err
				}
			}
			res.Ack = append(res.Ack, ev.EventID)
		case "question":
			fresh, err := questionReceipt(tx, ag.ID, ev, job.now)
			if err != nil {
				return res, err
			}
			if !fresh {
				res.Ack = append(res.Ack, ev.EventID)
				continue
			}
			added, err := s.insertQuestionOnce(tx, ag, ev, job.now, job)
			if err != nil {
				return res, err
			}
			if added {
				if err := recordQuestionReceipt(tx, ag.ID, ev, job.now); err != nil {
					return res, err
				}
				// Новый вопрос мог прийти по старой политике. Закрытие — вместе с пачкой.
				coverHost = true
			}
			res.Ack = append(res.Ack, ev.EventID)
		case "queue_drop":
			fresh, err := questionReceipt(tx, ag.ID, ev, job.now)
			if err != nil {
				return res, err
			}
			if fresh {
				if err := recordQuestionReceipt(tx, ag.ID, ev, job.now); err != nil {
					return res, err
				}
			}
			res.Ack = append(res.Ack, ev.EventID)
		}
		if err := ingest.RecordIPv6(tx, ag, ev); err != nil {
			return res, err
		}

		job.applied = append(job.applied, ev)
		if telemetryKind(ev.Kind) {
			job.serviceSeq = max(job.serviceSeq, ev.Seq)
		}
	}
	if coverHost || coverAll {
		hosts := []string{ag.HostID}
		if coverAll {
			var err error
			hosts, err = policyStrings(tx, "SELECT DISTINCT host_id FROM learn_questions WHERE status='open'")
			if err != nil {
				return res, err
			}
		}
		for _, h := range hosts {
			if err := closeCoveredQuestions(tx, h, job.now, func(id string) error { return s.flushQuestionRepeats(tx, job.now, id) }); err != nil {
				return res, err
			}
		}
	}
	job.staged = staged
	if err := s.noteSrc(tx, ag.ID, job.src); err != nil {
		return res, err
	}
	if floor := job.batch.QuestionPendingFrom; floor != nil {
		if err := s.confirmQuestions(tx, ag.ID, *floor); err != nil {
			return res, err
		}
	}

	return res, nil
}

// noteHealth держит пульс и инвентарь в памяти. На диск идёт только то, от чего
// зависят политика и список агентов: версия, backend, boot_id, адреса и порты SSH,
// и только при их смене. Второе значение — отказ события, как у прежнего приёма.
func (s *Server) noteHealth(tx *sql.Tx, ag ingest.Agent, ev protocol.Event, now int64) (string, error) {
	var p protocol.HealthPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return "", err
	}
	if p.FWBackend != "" {
		if p.FWBackend != "nftables" && p.FWBackend != "iptables" && p.FWBackend != "unknown" {
			return "invalid firewall backend", nil
		}
		if _, err := tx.Exec(`UPDATE agents SET fw_backend=?, scope_note=? WHERE agent_id=? AND (COALESCE(fw_backend,'')!=? OR COALESCE(scope_note,'')!=?)`,
			p.FWBackend, emptyNil(p.ScopeNote), ag.ID, p.FWBackend, p.ScopeNote); err != nil {
			return "", err
		}
	}
	if p.Version != "" {
		if _, err := tx.Exec(`UPDATE agents SET version=? WHERE agent_id=? AND COALESCE(version,'')!=?`, p.Version, ag.ID, p.Version); err != nil {
			return "", err
		}
	}
	if stopped := settingValue(tx, "agent_stopped:"+ag.HostID, ""); stopped != "" {
		at, _ := strconv.ParseInt(stopped, 10, 64)
		// A pulse from before the stop acknowledgement must not clear it.
		if ev.ObservedAtMS > at+2000 {
			if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, "agent_stopped:"+ag.HostID); err != nil {
				return "", err
			}
		}
	}
	// Инвентарь несёт только свежий alive. Сбой сбора, восстановление firewall
	// и запоздавший пульс из хвоста очереди порты и адреса не трогают.
	if !freshAlive(ag.DeliveryLane, ev, p, now) {
		return "", nil
	}
	if p.BootID != "" {
		// Живой экран сверяет boot соединения с этим полем: после перезагрузки сервера оно обязано смениться.
		if _, err := tx.Exec(`UPDATE agents SET boot_id=? WHERE agent_id=? AND COALESCE(boot_id,'')!=?`, p.BootID, ag.ID, p.BootID); err != nil {
			return "", err
		}
	}
	if p.Addresses == nil && p.OpenPorts == nil {
		return "", nil
	}
	var old struct {
		SSHPort   *int     `json:"ssh_port"`
		SSHPorts  []int    `json:"ssh_ports"`
		Addresses []string `json:"addresses"`
	}
	var oldRaw string
	if err := tx.QueryRow(`SELECT v FROM settings WHERE k=?`, "inventory:"+ag.HostID).Scan(&oldRaw); err == nil {
		_ = json.Unmarshal([]byte(oldRaw), &old)
	} else if err != sql.ErrNoRows {
		return "", err
	}
	sshChanged := p.SSHPort != nil && (old.SSHPort == nil || *old.SSHPort != *p.SSHPort) || !slices.Equal(old.SSHPorts, p.SSHPorts)
	if !sshChanged && slices.Equal(old.Addresses, p.Addresses) {
		return "", nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, "inventory:"+ag.HostID, string(raw)); err != nil {
		return "", err
	}
	if !sshChanged {
		return "", nil
	}
	// Стартовое правило SSH уходит с портами sshd этого хоста.
	if _, err = tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=?`, ag.HostID); err != nil {
		return "", err
	}
	if mon := settingValue(tx, "monitor_host_id", ""); mon != "" && mon == ag.HostID {
		return "", s.syncMonitorServiceRules(tx, mon)
	}
	return "", nil
}

// noteRuleDNS пишет пару имя–адрес, только если имя есть в правиле или группе
// и такой пары ещё нет. Прочие DNS-ответы живут только в памяти агента.
// true — пара записана и политика сдвинулась.
func noteRuleDNS(tx *sql.Tx, ag ingest.Agent, ev protocol.Event) (bool, error) {
	var p protocol.DNSPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return false, err
	}
	if p.Kind == "ptr" {
		return false, nil
	}
	ok, err := dnsTouchesPatterns(tx, p.Name)
	if err != nil || !ok {
		return false, err
	}
	fresh, err := dnsPairFresh(tx, p)
	if err != nil || !fresh {
		return false, err
	}
	ip, err := netipx.Parse(p.IP)
	if err != nil {
		return false, err
	}
	name := strings.ToLower(strings.TrimSuffix(p.Name, "."))
	res, err := tx.Exec(`INSERT INTO dns_seen(host_id, name, ip_bin, ip, first_seen_ms, last_seen_ms) VALUES(?,?,?,?,?,?)
		ON CONFLICT(host_id, name, ip_bin) DO NOTHING`,
		ag.HostID, name, netipx.Bin16(ip), netipx.Canonical(ip), ev.ObservedAtMS, ev.ObservedAtMS)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if err = bumpTrusted(tx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Server) noteSrc(tx *sql.Tx, agentID, src string) error {
	if src == "" {
		return nil
	}
	var cur string
	err := tx.QueryRow(`SELECT COALESCE(last_src_ip,'') FROM agents WHERE agent_id=?`, agentID).Scan(&cur)
	if err != nil {
		return err
	}
	if cur == src {
		return nil
	}
	_, err = tx.Exec(`UPDATE agents SET last_src_ip=? WHERE agent_id=?`, src, agentID)
	return err
}

// insertQuestionOnce пишет вопрос только когда такого открытого ещё нет.
// Повтор того же ключа диск не трогает.
func (s *Server) insertQuestionOnce(tx *sql.Tx, ag ingest.Agent, ev protocol.Event, now int64, jobs ...*batchJob) (bool, error) {
	var p protocol.QuestionPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return false, err
	}
	key := p.DedupKey
	if key == "" {
		key = strings.Join([]string{p.Direction, p.Protocol, p.RemoteIP, fmt.Sprint(p.RemotePort), p.ProcComm}, "|")
	}
	var id, status string
	var repeats int
	err := tx.QueryRow("SELECT question_id,status,repeats FROM learn_questions WHERE host_id=? AND dedup_key=? ORDER BY opened_at_ms DESC LIMIT 1", ag.HostID, key).Scan(&id, &status, &repeats)
	if err == nil {
		if status == "open" {
			n := max(p.Repeats, 1)
			key := ag.ID + "\\n" + ev.EventID
			store.OnFinish(tx, func(committed bool) {
				if !committed || len(jobs) > 0 && jobs[0].err != nil {
					return
				}
				s.qMu.Lock()
				defer s.qMu.Unlock()
				if s.qSeen == nil {
					s.qSeen = map[string]int64{}
				}
				if _, ok := s.qSeen[key]; ok {
					return
				}
				s.qSeen[key] = ev.Seq
				if s.qRep == nil {
					s.qRep = map[string]int{}
				}
				s.qRep[id] = max(s.qRep[id], repeats) + n
			})
			return false, nil
		}
		d, e := loadHostDecision(tx, ag.HostID, neverPrefixes(tx), settingValue(tx, "park_mode", "learn"))
		if e != nil {
			return false, e
		}
		if d.mode == "quarantine" {
			d.mode = d.plain
		}
		c := policy.Contact{Host: ag.HostID, Direction: p.Direction, Protocol: p.Protocol, RemoteIP: p.RemoteIP, LocalPort: p.LocalPort, RemotePort: p.RemotePort, Process: p.ProcPath}
		if ident, e := policy.ParseIdentity(p.ProcPath, ag.HostID, p.ProcComm); e == nil {
			c.Process, c.Cgroup, c.UID = ident.Path, ident.Cgroup, ident.UID
		}
		if !d.needsQuestion(c, now) {
			return false, nil
		}
	}

	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	n := p.Repeats
	if n < 1 {
		n = 1
	}
	_, err = tx.Exec(
		`INSERT INTO learn_questions(question_id, host_id, dedup_key, opened_at_ms, repeats, last_seen_ms, direction, protocol, local_port, remote_ip, remote_port, dns_name, proc_path, proc_comm, container, status)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open')`,
		idgen.NewV7(), ag.HostID, key, now, n, now, p.Direction, p.Protocol, p.LocalPort, p.RemoteIP, p.RemotePort, emptyNil(p.DNSName), emptyNil(p.ProcPath), emptyNil(p.ProcComm), emptyNil(p.Container),
	)
	return err == nil, err
}

func (s *Server) flushQuestionRepeats(tx *sql.Tx, now int64, ids ...string) error {
	s.qMu.Lock()
	rep := make(map[string]int, len(s.qRep))
	for id, n := range s.qRep {
		if len(ids) == 0 || slices.Contains(ids, id) {
			rep[id] = n
		}
	}
	s.qMu.Unlock()
	store.OnFinish(tx, func(committed bool) {
		s.qMu.Lock()
		defer s.qMu.Unlock()
		if !committed {
			return
		}
		for id, n := range rep {
			if s.qRep[id] == n {
				delete(s.qRep, id)
			}
		}
	})
	for id, n := range rep {
		if n < 1 {
			continue
		}
		if _, err := tx.Exec("UPDATE learn_questions SET repeats=MAX(repeats,?),last_seen_ms=MAX(last_seen_ms,?) WHERE question_id=?", n, now, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) persistSSHBrute(tx *sql.Tx, host string, ev protocol.Event, now int64, jobs ...*batchJob) error {
	var p protocol.SSHPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	addr, err := netipx.Parse(p.RemoteIP)
	if err != nil {
		return err
	}
	ip := netipx.Canonical(addr)
	var last int64
	err = tx.QueryRow("SELECT last_at_ms FROM ssh_brute WHERE remote_ip=? AND host_id=?", ip, host).Scan(&last)
	fresh := err == sql.ErrNoRows
	if err != nil && !fresh {
		return err
	}
	key := host + "\n" + ip
	s.ssh.mu.Lock()
	written := max(s.ssh.written[key], s.ssh.writing[tx][key])
	s.ssh.mu.Unlock()
	if !fresh && now-max(last, written) < 60000 {
		return nil
	}
	hits := s.ssh.unsaved(host, ip, now, fresh)
	if fresh && len(hits) < 5 || len(hits) == 0 {
		return nil
	}
	first, end := hits[0].at, hits[0].at
	for _, h := range hits {
		first = min(first, h.at)
		end = max(end, h.at)
	}
	if fresh {
		_, err = tx.Exec("INSERT INTO ssh_brute(remote_ip,host_id,attempts,first_at_ms,last_at_ms) VALUES(?,?,?,?,?)", ip, host, len(hits), first, end)
	} else {
		_, err = tx.Exec("UPDATE ssh_brute SET attempts=attempts+?,first_at_ms=MIN(first_at_ms,?),last_at_ms=MAX(last_at_ms,?) WHERE remote_ip=? AND host_id=?", len(hits), first, end, ip, host)
	}
	if err == nil {
		s.ssh.mu.Lock()
		if s.ssh.writing == nil {
			s.ssh.writing = map[*sql.Tx]map[string]int64{}
		}
		if s.ssh.writing[tx] == nil {
			s.ssh.writing[tx] = map[string]int64{}
		}
		s.ssh.writing[tx][key] = now
		s.ssh.mu.Unlock()
		store.OnFinish(tx, func(committed bool) {
			s.ssh.mu.Lock()
			defer s.ssh.mu.Unlock()
			delete(s.ssh.writing[tx], key)
			if len(s.ssh.writing[tx]) == 0 {
				delete(s.ssh.writing, tx)
			}
			if !committed || len(jobs) > 0 && jobs[0].err != nil {
				return
			}
			if s.ssh.written == nil {
				s.ssh.written = map[string]int64{}
			}
			s.ssh.written[key] = now
			if s.ssh.saved == nil {
				s.ssh.saved = map[string]bool{}
			}
			for _, h := range hits {
				s.ssh.saved[h.id] = true
			}
		})
	}
	return err
}

func (b *sshBook) unsaved(host, ip string, now int64, initial bool) []sshHit {
	b.mu.Lock()
	defer b.mu.Unlock()
	var hits []sshHit
	add := func(h sshHit) {
		if h.host != host || h.ip != ip || h.at > now {
			return
		}
		if initial {
			if h.at <= now-sshWindowMS {
				return
			}
		} else if b.saved[h.id] {
			return
		}
		hits = append(hits, h)
	}
	for _, h := range b.hits {
		add(h)
	}
	for _, list := range b.pend {
		for _, h := range list {
			add(h)
		}
	}
	return hits
}

// Persist pending rare summaries even when the last burst has stopped.
func (s *Server) flushSSHBrute(now int64) error {
	pairs := map[string]sshHit{}
	for _, h := range s.ssh.committed() {
		pairs[h.host+"\n"+h.ip] = h
	}
	return s.st.Update(func(tx *sql.Tx) error {
		for _, h := range pairs {
			raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: h.ip})
			if err := s.persistSSHBrute(tx, h.host, protocol.Event{Payload: raw}, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func emptyNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) applyPulse(ag *uiAgent) {
	s.pulseMu.Lock()
	t := s.hostSeen[ag.HostID]
	h, ok := s.hostInv[ag.HostID]
	fault := s.collectFault[ag.HostID]
	s.pulseMu.Unlock()
	ag.Last = t
	ag.Online = ag.Trust == "trusted" && t > store.NowMS()-60000
	if ok && h.QueueBytes != nil {
		ag.Queue = *h.QueueBytes
	}
	if fault != "" {
		ag.CollectFault = fault
	}
}

func (s *Server) applyServerPulse(sv *uiServer) {
	s.pulseMu.Lock()
	h, ok := s.hostInv[sv.HostID]
	s.pulseMu.Unlock()
	if !ok {
		return
	}
	if h.Addresses != nil {
		sv.Addresses = h.Addresses
	}
	if h.OpenPorts != nil {
		sv.OpenPorts = h.OpenPorts
	}
	if h.Listeners != nil {
		sv.Listeners = h.Listeners
	}
	if h.CPUPct != nil {
		sv.CPU = h.CPUPct
	}
	if h.RAMPct != nil {
		sv.RAM = h.RAMPct
	}
	if h.DiskPct != nil {
		sv.Disk = h.DiskPct
	}
}

func (s *Server) repSSHMemory(from, to int64, host string) ([][]string, error) {
	names, err := s.sshHostNames()
	if err != nil {
		return nil, err
	}
	now := store.NowMS()
	if to == 0 || to > now {
		to = now
	}
	from = to - 10*60*1000
	type group struct {
		ip, name, host string
		n              int
		last           int64
		saved          bool
	}
	groups := map[string]*group{}
	ensure := func(ip, hid string) *group {
		key := ip + "\n" + hid
		g := groups[key]
		if g == nil {
			name := names[hid]
			if name == "" {
				name = hid
			}
			g = &group{ip: ip, name: name, host: hid}
			groups[key] = g
		}
		return g
	}
	for _, h := range s.ssh.committed() {
		if h.at < from || h.at > to {
			continue
		}
		if host != "" && host != "all" && h.host != host {
			continue
		}
		g := ensure(h.ip, h.host)
		g.n++
		if h.at > g.last {
			g.last = h.at
		}
	}
	rows, err := s.st.DB.Query(`SELECT remote_ip, host_id, attempts, last_at_ms FROM ssh_brute`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, hid string
		var attempts, last int64
		if err := rows.Scan(&ip, &hid, &attempts, &last); err != nil {
			return nil, err
		}
		if host != "" && host != "all" && hid != host {
			continue
		}
		g := ensure(ip, hid)
		g.saved = true
		if last > g.last {
			g.last = last
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out [][]string
	for _, g := range groups {
		st := "наблюдаем"
		if g.saved || g.n >= 5 {
			st = "порог"
		}
		out = append(out, []string{g.ip, g.name, strconv.Itoa(g.n), fmtMS(g.last), st})
	}
	return out, nil
}

func (s *Server) visibleReports() []uiReportMeta {
	all := reportCatalog()

	var out []uiReportMeta
	for _, m := range all {
		switch m.ID {
		case "scanners", "sshfail", "blocked", "persist":
			out = append(out, m)
		}
	}
	return out
}
