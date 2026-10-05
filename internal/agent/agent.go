package agent

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"context"
	"netmonitor/internal/collect"
	"netmonitor/internal/fw"
	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/outbox"
	pol "netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

// Version — версия сборки; tools/build_release.py ставит сюда метку релиза.
var Version = "1.0.5"

type Config struct {
	Pin         string
	DataDir     string
	Monitor     string
	Token       string
	ForceEnroll bool
}

type firewall interface {
	Backend() string
	Apply(fw.Policy) error
	Alive() bool
}

type Agent struct {
	startRemoval  func(string) error         // Optional test seam; production uses the durable worker.
	startUpdate   func(string, string) error // Optional test seam; production replaces the binary.
	updating      string                     // Команда обновления, уже запущенная этим процессом.
	managed       bool
	rules, groups []pol.Rule
	process       collect.ProcessIndex
	policyRev     int64
	fwMu          sync.RWMutex
	firewall      firewall
	actualRev     *int64
	fwError       string
	askedMu       sync.Mutex
	cfg           Config
	st            *store.Store
	client        *http.Client
	id            string
	hostID        string
	kept          bool
	bootID        string
	rev           int64
	applied       []fw.Desired
	scan          *collect.Tracker
	nets          []netip.Prefix
	allows        []netip.Prefix
	never         []netip.Prefix
	lan, own      []netip.Prefix
	dockerIfaces  []string
	dockerNets    []netip.Prefix
	// Имена контейнеров под своим мьютексом: читаются и из транзакции сборщика,
	// где ждать fwMu нельзя (применение политики держит fwMu и ждёт БД).
	contMu        sync.Mutex
	containers    map[string]string
	containersAt  time.Time
	containerNets []netip.Prefix
	nameMu        sync.Mutex
	resolved      map[string]resolvedName
	observeDocker bool
	skipIfaces    map[string]bool
	mode          string
	asked         map[string]time.Time
}

func Open(cfg Config) (*Agent, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.OpenAgent(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, st: st, bootID: bootID(), scan: collect.NewTracker()}
	if err := a.ensureEnrolled(); err != nil {
		st.Close()
		return nil, err
	}
	a.skipIfaces = loadSkipIfaces(cfg.DataDir, st.DB)
	return a, nil
}

func (a *Agent) Close() error { return a.st.Close() }

func (a *Agent) ID() string { return a.id }

// AlreadyKnown is set when a repeat install kept the current certificate.
func (a *Agent) AlreadyKnown() bool { return a.kept }

func (a *Agent) ensureEnrolled() error {
	id, err := meta(a.st.DB, "agent_id")
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if id != "" {
		a.id = id
		a.hostID, err = meta(a.st.DB, "host_id")
		if err != nil {
			return err
		}
		mon, err := meta(a.st.DB, "monitor")
		if err != nil {
			return err
		}
		if a.cfg.Monitor == "" {
			a.cfg.Monitor = mon
		}
		if a.cfg.Token != "" && a.cfg.ForceEnroll {
			// A new token must not mint a second agent while this monitor still accepts the certificate.
			keep, err := a.keepIfKnown()
			if err != nil {
				return err
			}
			if keep {
				a.kept = true
				if a.cfg.Monitor != mon {
					return a.rememberMonitor(a.cfg.Monitor)
				}
				return nil
			}
			return a.enroll()
		}
		return a.loadClient()
	}
	if a.cfg.Token == "" || a.cfg.Monitor == "" {
		return fmt.Errorf("нужны --monitor и --token для первой установки")
	}
	return a.enroll()
}

// keepIfKnown reports whether the monitor still accepts this certificate.
// A verified pin that no longer matches the stored CA means the monitor was replaced.
func (a *Agent) keepIfKnown() (bool, error) {
	pinOK, err := a.confirmPin()
	if err != nil {
		return false, err
	}
	if err := a.loadClient(); err != nil {
		if pinOK {
			return false, nil
		}
		return false, err
	}
	prev := a.client.Timeout
	a.client.Timeout = 12 * time.Second
	defer func() { a.client.Timeout = prev }()
	// rev -1 returns at once. A matching revision would wait out the long poll.
	req, err := http.NewRequest(http.MethodPost, a.monitorURL()+"/v1/poll", bytes.NewReader([]byte(`{"rev":-1}`)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		if pinOK && tlsRejected(err) {
			return false, nil
		}
		return false, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return false, err
	}
	if res.StatusCode == http.StatusOK {
		return true, nil
	}
	if res.StatusCode == http.StatusUnauthorized {
		msg := string(b)
		if strings.Contains(msg, "отозван") || strings.Contains(msg, "неизвестный сертификат") {
			return false, nil
		}
	}
	return false, fmt.Errorf("poll %s: %s", res.Status, bytes.TrimSpace(b))
}

func (a *Agent) confirmPin() (bool, error) {
	if a.cfg.Pin == "" {
		return false, nil
	}
	cfg, err := tlsutil.PinnedTLSConfig(a.cfg.Pin)
	if err != nil {
		return false, err
	}
	cl := &http.Client{Transport: &http.Transport{
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 8 * time.Second,
	}, Timeout: 12 * time.Second}
	res, err := cl.Get(a.monitorURL() + "/")
	if err != nil {
		return false, err
	}
	res.Body.Close()
	return true, nil
}

func (a *Agent) rememberMonitor(m string) error {
	return a.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('monitor',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, m)
		return err
	})
}

func tlsRejected(err error) bool {
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid)
}

func (a *Agent) enroll() error {
	body, _ := json.Marshal(protocol.EnrollReq{
		Token:    a.cfg.Token,
		Hostname: hostname(),
		BootID:   a.bootID,
		Version:  Version,
	})
	url := a.monitorURL() + "/v1/enroll"
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("enrollment requires HTTPS")
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	pinTLS, err := tlsutil.PinnedTLSConfig(a.cfg.Pin)
	if err != nil {
		return err
	}
	tr := &http.Transport{
		TLSClientConfig:     pinTLS,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	cl := &http.Client{Transport: tr, Timeout: 12 * time.Second}
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll %s: %s", res.Status, b)
	}
	var er protocol.EnrollRes
	if err := json.Unmarshal(b, &er); err != nil {
		return err
	}
	tlsDir := filepath.Join(a.cfg.DataDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "ca.crt"), []byte(er.CAPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "client.crt"), []byte(er.CertPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tlsDir, "client.key"), []byte(er.KeyPEM), 0o600); err != nil {
		return err
	}
	a.id, a.hostID = er.AgentID, er.HostID
	if err := a.st.Update(func(tx *sql.Tx) error {
		for k, v := range map[string]string{
			"agent_id": a.id,
			"host_id":  a.hostID,
			"monitor":  a.cfg.Monitor,
			"boot_id":  a.bootID,
		} {
			if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`DELETE FROM outbox`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM checkpoints`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM local_questions`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('queue_bytes','0') ON CONFLICT(k) DO UPDATE SET v='0'`); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return a.loadClient()
}

func (a *Agent) loadClient() error {
	tlsDir := filepath.Join(a.cfg.DataDir, "tls")
	ca, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		return err
	}
	crt, err := os.ReadFile(filepath.Join(tlsDir, "client.crt"))
	if err != nil {
		return err
	}
	key, err := os.ReadFile(filepath.Join(tlsDir, "client.key"))
	if err != nil {
		return err
	}
	cfg, err := tlsutil.ClientTLSConfig(ca, crt, key)
	if err != nil {
		return err
	}
	host, _, err := parseMonitor(a.cfg.Monitor)
	if err == nil && host != "" {
		cfg.ServerName = host
	}
	a.client = &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: false, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}, Timeout: 45 * time.Second}
	return nil
}

func (a *Agent) Enqueue(kind string, priority int, payload any) error {
	return a.st.Update(func(tx *sql.Tx) error { return enqueueTx(tx, kind, priority, payload) })
}
func enqueueTx(tx *sql.Tx, kind string, priority int, payload any) error {
	return outbox.Insert(tx, kind, priority, payload, store.NowMS())
}
func logAgentError(operation string, err error) {
	if err != nil {
		log.Printf("%s: %v", operation, err)
	}
}

func (a *Agent) Flush() error { return a.flushLane("") }
func (a *Agent) flushLane(lane string) error {
	if a.client == nil {
		if err := a.loadClient(); err != nil {
			return err
		}
	}
	type row struct {
		id, kind, payload string
		seq, observed     int64
	}
	var rows []row
	var pendingFrom int64
	query := "SELECT event_id,seq,kind,payload,created_at_ms FROM outbox"
	var args []any
	switch lane {
	case "urgent", "heartbeat":
		query += " WHERE lane=? AND created_at_ms>=? ORDER BY seq DESC LIMIT 200"
		args = []any{lane, store.NowMS() - 30000}
	case "history":
		query += " WHERE lane='history' OR created_at_ms<? ORDER BY seq LIMIT 200"
		args = []any{store.NowMS() - 30000}
	default:
		query += " ORDER BY priority DESC,seq LIMIT 200"
	}
	err := a.st.Update(func(tx *sql.Tx) error {
		q, err := tx.Query(query, args...)
		if err != nil {
			return err
		}
		defer q.Close()
		var sentQuestions []string
		for q.Next() {
			var r row
			if err := q.Scan(&r.id, &r.seq, &r.kind, &r.payload, &r.observed); err != nil {
				return err
			}
			rows = append(rows, r)
			if r.kind == "question" {
				sentQuestions = append(sentQuestions, r.id)
			}
		}
		if err := q.Err(); err != nil {
			return err
		}
		if err := q.Close(); err != nil {
			return err
		}
		if err := tx.QueryRow(`SELECT COALESCE(MIN(seq),COALESCE((SELECT CAST(v AS INTEGER) FROM meta WHERE k='next_seq'),0)+1) FROM outbox`).Scan(&pendingFrom); err != nil {
			return err
		}
		return outbox.MarkQuestionsSent(tx, sentQuestions)
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	batch := protocol.Batch{Lane: lane, PendingFrom: &pendingFrom}
	for _, r := range rows {
		batch.Events = append(batch.Events, protocol.Event{
			EventID:      r.id,
			Seq:          r.seq,
			Kind:         r.kind,
			ObservedAtMS: r.observed,
			Payload:      json.RawMessage(r.payload),
		})
	}
	body, _ := json.Marshal(batch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.monitorURL()+"/v1/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		log.Printf("flush: %v", err)
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 && res.StatusCode != 409 {
		log.Printf("batch %s: %s", res.Status, b)
		return fmt.Errorf("batch %s: %s", res.Status, b)
	}
	var ack protocol.Ack
	if err := json.Unmarshal(b, &ack); err != nil {
		log.Printf("flush: %s %s", res.Status, b)
		return fmt.Errorf("batch %s: %s", res.Status, b)
	}
	if ack.Error != "" {
		log.Printf("flush: ack %d err %s", len(ack.Ack), ack.Error)
	}
	sent := map[string]bool{}
	for _, r := range rows {
		sent[r.id] = true
	}
	for _, id := range ack.Ack {
		if !sent[id] {
			return fmt.Errorf("ACK contains unsent event")
		}
	}
	return a.st.Update(func(tx *sql.Tx) error {
		for _, id := range ack.Ack {
			if _, err := tx.Exec("DELETE FROM local_questions WHERE question_id=?", id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM outbox WHERE event_id=?`, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *Agent) Heartbeat() error {
	logAgentError("conntrack health", a.conntrackHealth())
	note := runtime.GOOS + " " + Version
	if free, err := outbox.FreeBytes(a.cfg.DataDir); err == nil {
		if err = a.st.Update(func(tx *sql.Tx) error { return outbox.Capacity(tx, free, store.NowMS()) }); err != nil {
			return err
		}
	} else {
		note += "; disk space unavailable: " + err.Error()
	}
	var qbytes int64
	if err := a.st.DB.QueryRow("SELECT COALESCE((SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_bytes'),0)").Scan(&qbytes); err != nil {
		return err
	}
	for _, suffix := range []string{"", "-wal"} {
		if info, e := os.Stat(a.st.Path() + suffix); e == nil {
			note += fmt.Sprintf("; %s=%d", filepath.Base(a.st.Path()+suffix), info.Size())
		}
	}

	a.fwMu.RLock()
	backend := fw.Backend()
	if a.firewall != nil {
		backend = a.firewall.Backend()
	}
	skip := a.skipIfaces
	a.fwMu.RUnlock()
	var addresses []string
	for _, ip := range collect.LocalView(skip).Local {
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			addresses = append(addresses, ip.String())
		}
	}
	ports, portsErr := collect.ListeningPorts("")
	if portsErr != nil {
		logAgentError("listening ports", portsErr)
	}
	res := collect.HostResources()
	sshPort := collect.SSHListenPort("")
	var listens []protocol.ListenPort
	for _, l := range collect.ListeningList("") {
		listens = append(listens, protocol.ListenPort{Proto: l.Proto, Port: l.Port, Proc: l.Proc, Desc: l.Desc})
	}
	h := protocol.HealthPayload{Addresses: addresses, OpenPorts: ports, SSHPort: &sshPort, SSHPorts: collect.SSHListenPorts(""), Listeners: listens, Kind: "alive", BootID: a.bootID, Version: Version, QueueBytes: &qbytes, Note: note, FWBackend: backend, ScopeNote: a.scopeNote()}
	if res.OK {
		cpu, ram, disk := res.CPU, res.RAM, res.Disk
		h.CPUPct, h.RAMPct, h.DiskPct = &cpu, &ram, &disk
	}
	return a.Enqueue("health", 10, h)
}

func (a *Agent) Run() error {
	if err := collect.EnableKernel(); err != nil {
		logAgentError("collector setup", err)
		_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "collector_setup", Note: err.Error()})
	}
	logAgentError("local firewall", a.loadLocalFW())
	stop := make(chan struct{})
	defer close(stop)
	ready := make(chan struct{}, 1)
	go a.watchCT(stop, ready)
	go a.watchDNS(stop)
	go a.watchNFLog(stop)
	go a.pollLoop()
	go a.watchdog()
	go a.watchLinks(stop)
	// Three independent requests: slow backlog cannot block heartbeat or a new decision.
	for _, lane := range []string{"urgent", "heartbeat", "history"} {
		go a.deliver(stop, lane)
	}
	if err := a.Heartbeat(); err != nil {
		return err
	}
	tHB := time.NewTicker(10 * time.Second)
	defer tHB.Stop()
	tDump := time.NewTicker(15 * time.Second)
	defer tDump.Stop()
	tSSH := time.NewTicker(10 * time.Second)
	defer tSSH.Stop()

	subscribed := false
	for {
		select {
		case <-ready:
			subscribed = true
			a.dumpOnce()
			_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_ready"})
		case <-tHB.C:
			logAgentError("heartbeat", a.Heartbeat())
		case <-tDump.C:
			logAgentError("foreign firewall observation", collect.ObserveForeignFirewall())
			if subscribed {
				a.dumpOnce()
			}
		case <-tSSH.C:
			a.sshOnce()

		}
	}
}
func (a *Agent) deliver(stop <-chan struct{}, lane string) {
	delay := 200 * time.Millisecond
	for {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}
		if err := a.flushLane(lane); err != nil {
			delay = min(5*time.Second, max(time.Second, delay*2))
		} else {
			delay = 200 * time.Millisecond
		}
	}
}

func (a *Agent) dumpOpts() collect.DumpOpts {
	monIP, monPort := a.monitorAddr()
	a.fwMu.RLock()
	skip := a.skipIfaces
	lan, own := a.lan, a.own
	observe := a.observeDocker
	a.fwMu.RUnlock()
	view := collect.LocalView(skip)
	return collect.DumpOpts{
		HostID:        a.hostID,
		BootID:        a.bootID,
		Local:         view.Local,
		LAN:           lan,
		Overlay:       view.Overlay,
		Own:           own,
		DockerNets:    view.BridgeNets,
		SkipIfaces:    skip,
		AddrIface:     view.AddrIface,
		ObserveDocker: observe,
		Monitor:       monIP,
		MonitorPort:   monPort,
		NowMS:         store.NowMS(),
		MonoMS:        collect.MonotonicMS(),
		Namespace:     collect.Namespace(),
		Process:       a.process.Lookup,
		Container:     a.containerName,
	}
}

// containerName ищет имя по адресу контейнера. Новый контейнер ещё не в карте:
// перечитываем её сразу, но не чаще раза в секунду, иначе первый вопрос
// по свежему контейнеру придёт без имени и не склеится со следующим.
func (a *Agent) containerName(ip string) string {
	a.contMu.Lock()
	defer a.contMu.Unlock()
	if name, ok := a.containers[ip]; ok || ip == "" {
		return name
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || time.Since(a.containersAt) < time.Second || !inPrefixes(addr.Unmap(), a.containerNets) {
		return ""
	}
	a.containers = collect.ContainerNames("")
	a.containersAt = time.Now()
	return a.containers[ip]
}

func (a *Agent) refreshContainers(nets []netip.Prefix) {
	names := collect.ContainerNames("")
	a.contMu.Lock()
	a.containers, a.containersAt = names, time.Now()
	a.containerNets = append([]netip.Prefix(nil), nets...)
	a.contMu.Unlock()
}

// setContainerNets только сообщает, где искать контейнеры; файлы читает промах.
func (a *Agent) setContainerNets(nets []netip.Prefix) {
	a.contMu.Lock()
	a.containerNets = append([]netip.Prefix(nil), nets...)
	a.contMu.Unlock()
}

func inPrefixes(ip netip.Addr, nets []netip.Prefix) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *Agent) dumpOnce() {
	snapshot := collect.MonotonicMS()
	entries, err := collect.DumpAll()
	if err != nil {
		log.Printf("dump: %v", err)
		logAgentError("enqueue", a.Enqueue("health", 8, protocol.HealthPayload{Kind: "dump_error", Note: err.Error()}))
		return
	}
	log.Printf("dump: %d flows", len(entries))
	opt := a.dumpOpts()
	opt.SnapshotMono = snapshot
	if err := a.st.Update(func(tx *sql.Tx) error {
		return collect.ApplyDump(tx, entries, opt)
	}); err != nil {
		log.Printf("dump SQL: %v", err)
		return
	}
	for _, e := range entries {
		a.noteScan(e)
		if e.Unreplied || e.State == "SYN_SENT" {
			a.noteLearn(e)
		}
	}
}

func (a *Agent) noteLearnSets() {
	for _, h := range fw.LearnHits() {
		ip := h.IP.Unmap().String()
		lp, rp := 0, h.Port
		if h.Dir == "in" {
			lp, rp = h.Port, 0
		}
		a.enqueueLearn(h.Dir, h.Proto, ip, lp, rp)
	}
}

func (a *Agent) noteOnce(e collect.Entry) {
	a.fwMu.RLock()
	nets := a.dockerNets
	a.fwMu.RUnlock()
	dir, lip, remoteIP, lport, rport := collect.ClassifySessionNets(e, collect.LocalAddrs(), nets)
	if dir == "" || dir == "unknown" || collect.HostSide(dir) || remoteIP == "" {
		return
	}
	var proc collect.Process
	addr, _ := netip.ParseAddr(lip)
	if !inPrefixes(addr.Unmap(), nets) && !inPrefixes(e.ReplySrc.Unmap(), nets) {
		proc = a.process.Lookup(e)
	}
	lp, rp := 0, 0
	if lport != nil {
		lp = *lport
	}
	if rport != nil {
		rp = *rport
	}
	c := pol.Contact{Host: a.hostID, Direction: dir, Protocol: e.Protocol, RemoteIP: remoteIP, LocalPort: lp, RemotePort: rp, Process: proc.Path, Cgroup: proc.Cgroup, UID: proc.UID}
	unlock, err := a.lockFirewall()
	if err != nil {
		return
	}
	now := store.NowMS()
	if _, ok := pol.Evaluate(a.groups, a.hostID, c, now); ok {
		unlock()
		return
	}
	d, ok := pol.Evaluate(a.rules, a.hostID, c, now)
	id := ""
	if ok && d.Action == "allow" {
		for _, r := range a.rules {
			if r.ID == d.ID && r.Once && !r.OnceUsed {
				id = r.ID
				break
			}
		}
	}
	if id == "" {
		unlock()
		return
	}
	err = a.consumeOnceLocked(id)
	unlock()
	if err != nil {
		log.Printf("once consume: %v", err)
	}
}

func (a *Agent) noteLearn(e collect.Entry, dropped ...bool) {
	// A reply belongs to an existing contact, even if an alert group logged it
	// before the policy tail. Keep its firewall event, but do not ask again.
	if e.CTDirectionKnown && e.CTReply {
		return
	}
	a.fwMu.RLock()
	managed := a.managed
	a.fwMu.RUnlock()
	if managed && (len(dropped) == 0 || !dropped[0]) {
		return
	}
	a.fwMu.RLock()
	mode, _ := fw.SplitMode(a.mode)
	a.fwMu.RUnlock()
	if mode != "learn" && !managed {
		return
	}
	a.fwMu.RLock()
	nets := a.dockerNets
	a.fwMu.RUnlock()
	dir, lip, remoteIP, lport, rport := collect.ClassifySessionNets(e, collect.LocalAddrs(), nets)
	if dir == "" || dir == "unknown" || collect.HostSide(dir) || remoteIP == "" {
		return
	}
	// Ответ на наш исходящий приходит на input и похож на вход на случайный порт.
	if !e.CTDirectionKnown && dir == "in" && e.TCPReply() && lport != nil && !collect.Listening(e.Protocol, *lport) {
		return
	}
	// Адрес контейнера: при исходе — локальный, при входе через DNAT — ответчик.
	cip := ""
	if ip, err := netip.ParseAddr(lip); err == nil && inPrefixes(ip.Unmap(), nets) {
		cip = ip.Unmap().String()
	} else if e.ReplySrc.IsValid() && inPrefixes(e.ReplySrc.Unmap(), nets) {
		cip = e.ReplySrc.Unmap().String()
	}
	// У контейнера нет процесса хоста: на опубликованном порту поиск нашёл бы
	// docker-proxy, а правила по процессу в forward не действуют.
	var proc collect.Process
	if cip == "" {
		proc = a.process.Lookup(e)
	}
	if a.flowAllowed(e, dir, remoteIP, lport, rport, proc) {
		return
	}
	rp, lp := 0, 0
	if rport != nil {
		rp = *rport
	}
	if lport != nil {
		lp = *lport
	}
	a.enqueueLearnProcess(dir, e.Protocol, remoteIP, lp, rp, proc, cip)
}

func (a *Agent) enqueueLearn(dir, proto, remoteIP string, lp, rp int) {
	a.enqueueLearnProcess(dir, proto, remoteIP, lp, rp, collect.Process{}, "")
}

// containerIP — адрес контейнера, если соединение его. Ключ склейки строится по
// адресу: имя из config.v2.json у свежего контейнера появляется не сразу.
func (a *Agent) enqueueLearnProcess(dir, proto, remoteIP string, lp, rp int, proc collect.Process, containerIP string) {
	a.fwMu.RLock()
	defer a.fwMu.RUnlock()
	a.askedMu.Lock()
	defer a.askedMu.Unlock()
	if mode, _ := fw.SplitMode(a.mode); mode != "learn" && !a.managed {
		return
	}
	if !a.managed && servicePortAllowed(dir, proto, lp, rp) {
		return
	}
	rip, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return
	}
	rip = rip.Unmap()
	if a.monitorIP().IsValid() && rip == a.monitorIP().Unmap() {
		return
	}
	for _, p := range a.nets {
		if p.Contains(rip) {
			return
		}
	}
	for _, p := range a.allows {
		if p.Contains(rip) {
			return
		}
	}
	if a.managed && !a.questionLocked(pol.Contact{Direction: dir, Protocol: proto, RemoteIP: remoteIP, LocalPort: lp, RemotePort: rp, Process: proc.Path, Cgroup: proc.Cgroup, UID: proc.UID}) {
		return
	}
	qport := rp
	if dir == "in" {
		qport = lp
	}
	key := dir + "|" + proto + "|" + rip.String() + "|" + strconv.Itoa(qport) + "|" + proc.Path + "|" + proc.Cgroup
	container := ""
	if containerIP != "" {
		key += "|▣" + containerIP
		container = a.containerName(containerIP)
	}
	log.Printf("question %s", key)
	err = a.Enqueue("question", 7, protocol.QuestionPayload{
		Direction: dir, Protocol: proto, RemoteIP: rip.String(), RemotePort: rp, LocalPort: lp, DedupKey: key, ProcComm: proc.Comm, ProcPath: pol.FormatIdentity(proc.Path, proc.UID, proc.Cgroup), Container: container, Repeats: 1,
	})
	if err != nil {
		log.Printf("queue question: %v", err)
	}
}

func (a *Agent) flowAllowed(e collect.Entry, dir, remote string, lport, rport *int, proc collect.Process) bool {
	a.fwMu.RLock()
	defer a.fwMu.RUnlock()
	if a.managed {
		lp, rp := 0, 0
		if lport != nil {
			lp = *lport
		}
		if rport != nil {
			rp = *rport
		}
		return !a.questionLocked(pol.Contact{Host: a.hostID, Direction: dir, Protocol: e.Protocol, RemoteIP: remote, LocalPort: lp, RemotePort: rp, Process: proc.Path, Cgroup: proc.Cgroup, UID: proc.UID})
	}
	_, monitorPort := a.monitorAddr()
	if collect.Skip(e, a.monitorIP(), monitorPort) {
		return true
	}
	lp, rp := 0, 0
	if lport != nil {
		lp = *lport
	}
	if rport != nil {
		rp = *rport
	}
	if servicePortAllowed(dir, e.Protocol, lp, rp) {
		return true
	}
	rip, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	rip = rip.Unmap()
	if a.monitorIP().IsValid() && rip == a.monitorIP().Unmap() {
		return true
	}
	for _, p := range a.nets {
		if p.Contains(rip) {
			return true
		}
	}
	for _, p := range a.allows {
		if p.Contains(rip) {
			return true
		}
	}
	return false
}

func (a *Agent) noteScan(e collect.Entry) {
	if a.scan == nil {
		return
	}
	_, monPort := a.monitorAddr()
	hit := a.scan.Observe(e, collect.LocalAddrs(), time.Now(), monPort)
	if hit == nil {
		return
	}
	log.Printf("scan %s ports %v", hit.IP, hit.Ports)
	logAgentError("enqueue", a.Enqueue("scan", 9, protocol.ScanPayload{IP: hit.IP.Unmap().String(), Ports: hit.Ports, Attempts: hit.Attempts}))
}

func (a *Agent) saveSSH(hits []collect.SSHFail, next string) error {
	return a.st.Update(func(tx *sql.Tx) error {
		for _, h := range hits {
			if err := enqueueTx(tx, "ssh", 8, protocol.SSHPayload{RemoteIP: h.IP, User: h.User, Note: h.Note, ObservedAtMS: h.AtMS}); err != nil {
				return err
			}
		}
		if next != "" {
			_, err := tx.Exec("INSERT INTO meta(k,v) VALUES('ssh_cursor',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", next)
			return err
		}
		return nil
	})
}
func (a *Agent) sshOnce() {
	cur, err := meta(a.st.DB, "ssh_cursor")
	if err != nil && err != sql.ErrNoRows {
		log.Printf("ssh cursor: %v", err)
		return
	}
	hits, next, err := collect.ReadSSHFailures(cur)
	if err != nil {
		log.Printf("ssh journal: %v", err)
		return
	}
	if err = a.saveSSH(hits, next); err != nil {
		log.Printf("ssh SQL: %v", err)
		return
	}
}

func (a *Agent) watchCT(stop <-chan struct{}, ready chan<- struct{}) {
	type event struct {
		e    collect.Entry
		kind string
		opt  collect.DumpOpts
	}
	events := make(chan event, 4096)
	var lost atomic.Int64
	go func() {
		for {
			err := collect.WatchReady(stop, func(e collect.Entry, kind string) {
				opt := a.dumpOpts()
				if collect.Skip(e, opt.Monitor, opt.MonitorPort) {
					return
				}
				select {
				case events <- event{e, kind, opt}:
				default:
					lost.Add(1)
				}
			}, func() {
				select {
				case ready <- struct{}{}:
				default:
				}
			})
			select {
			case <-stop:
				return
			default:
			}
			_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_gap", Note: fmt.Sprint(err) + "; exact count unknown"})
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	for {
		select {
		case <-stop:
			return
		case ev := <-events:
			if n := lost.Swap(0); n > 0 {
				_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_gap", LostEvents: &n, Note: "collector channel full"})
				select {
				case ready <- struct{}{}:
				default:
				}
			}
			if err := a.st.Update(func(tx *sql.Tx) error { return collect.ApplyEvent(tx, ev.e, ev.kind, ev.opt) }); err != nil {
				logAgentError("conntrack SQL", err)
				lost.Add(1)
				_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_gap", Note: err.Error()})
				continue
			}
			if ev.kind == "new" {
				a.noteScan(ev.e)
				a.noteOnce(ev.e)
				a.noteLearn(ev.e)
			}
		}
	}
}
func (a *Agent) watchDNS(stop <-chan struct{}) {
	for {
		err := collect.ListenDNS(stop, func(r collect.DNSRecord) {
			logAgentError("DNS queue", a.Enqueue("dns", 6, protocol.DNSPayload{Name: r.Name, IP: r.IP, Kind: r.Kind}))
		})
		select {
		case <-stop:
			return
		default:
		}
		_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "dns_error", Note: fmt.Sprint(err)})
		select {
		case <-stop:
			return
		case <-time.After(time.Second):
		}
	}
}

func (a *Agent) monitorAddr() (netip.Addr, int) {
	host, port, _ := parseMonitor(a.cfg.Monitor)
	p := 8443
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			p = n
		}
	}
	if host == "" {
		return netip.Addr{}, p
	}
	a2, err := netipx.Parse(host)
	if err != nil {
		return netip.Addr{}, p
	}
	return a2, p
}

func meta(db *sql.DB, k string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	return v, err
}

func loadSkipIfaces(dataDir string, db *sql.DB) map[string]bool {
	out := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		out[s] = true
	}
	if v, err := meta(db, "skip_ifaces"); err == nil {
		for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == ';' || r == ' ' }) {
			add(p)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "skip-ifaces")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			add(line)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a *Agent) scopeNote() string {
	note := "агент не видит пакеты, отброшенные до virtio; наблюдается трафик этого сервера в основном сетевом пространстве"
	a.fwMu.RLock()
	skip := a.skipIfaces
	a.fwMu.RUnlock()
	if len(skip) == 0 {
		return note
	}
	names := make([]string, 0, len(skip))
	for n := range skip {
		names = append(names, n)
	}
	sort.Strings(names)
	return note + "; выключены интерфейсы: " + strings.Join(names, ", ")
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err == nil {
		return string(bytes.TrimSpace(b))
	}
	return idgen.NewV7()
}

func (a *Agent) monitorURL() string {
	m := a.cfg.Monitor
	if m == "" {
		m, _ = meta(a.st.DB, "monitor")
	}
	if !hasScheme(m) {
		return "https://" + m
	}
	return m
}

func hasScheme(s string) bool {
	return len(s) > 8 && (s[:7] == "http://" || s[:8] == "https://")
}

func parseMonitor(m string) (host, port string, err error) {
	m = strings.TrimPrefix(m, "https://")
	m = strings.TrimPrefix(m, "http://")
	if h, p, err := net.SplitHostPort(m); err == nil {
		return h, p, nil
	}
	return m, "8443", nil
}

func servicePortAllowed(dir, proto string, lp, rp int) bool {
	if dir == "in" && proto == "tcp" && lp == 22 {
		return true
	}
	if dir == "out" && (proto == "tcp" || proto == "udp") && rp == 53 {
		return true
	}
	if dir == "out" && proto == "udp" && rp == 123 {
		return true
	}
	if proto == "udp" {
		if dir == "out" && (lp == 68 && rp == 67 || lp == 546 && rp == 547) {
			return true
		}
		if dir == "in" && (lp == 68 && rp == 67 || lp == 546 && rp == 547) {
			return true
		}
	}
	return false
}

func (a *Agent) watchNFLog(stop <-chan struct{}) {
	type record struct {
		p protocol.FirewallPayload
		e collect.Entry
	}
	events := make(chan record, 4096)
	go func() {
		for {
			err := collect.ListenNFLog(stop, func(p protocol.FirewallPayload, e collect.Entry) {
				select {
				case events <- record{p, e}:
				case <-stop:
				}
			}, func(err error) {
				_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "nflog_gap", Note: err.Error()})
			})
			select {
			case <-stop:
				return
			default:
			}
			_ = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "nflog_error", Note: fmt.Sprint(err)})
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	agg := collect.FirewallLog{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	emit := func(ps []protocol.FirewallPayload) {
		for _, p := range ps {
			logAgentError("NFLOG queue", a.Enqueue("firewall", 8, p))
		}
	}
	for {
		select {
		case <-stop:
			return
		case r := <-events:
			emit(agg.Observe(r.p, time.Now()))
			a.noteLearn(r.e, true)
			a.noteScan(r.e)
		case now := <-tick.C:
			emit(agg.Flush(now))
		}
	}
}

func (a *Agent) conntrackHealth() error {
	stats, err := collect.ConntrackFailures()
	if err != nil {
		return a.Enqueue("health", 10, protocol.HealthPayload{Kind: "conntrack_stats_error", Note: err.Error()})
	}
	return a.st.Update(func(tx *sql.Tx) error {
		key := "ct_failures:" + a.bootID
		old := map[string]uint64{}
		var raw string
		err := tx.QueryRow("SELECT v FROM meta WHERE k=?", key).Scan(&raw)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil {
			if err = json.Unmarshal([]byte(raw), &old); err != nil {
				return err
			}
			for name, n := range stats {
				if n > old[name] {
					if err := enqueueTx(tx, "health", 10, protocol.HealthPayload{Kind: "conntrack_gap", Note: fmt.Sprintf("kernel %s increased by %d", name, n-old[name])}); err != nil {
						return err
					}
				}
			}
		}
		body, err := json.Marshal(stats)
		if err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", key, string(body))
		return err
	})
}

// Caller holds fwMu. Manual blocks precede groups and user rules.
func (a *Agent) questionLocked(c pol.Contact) bool {
	ip, err := netip.ParseAddr(c.RemoteIP)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip == a.monitorIP() {
		return false
	}
	for _, n := range a.never {
		if n.Contains(ip) {
			return false
		}
	}
	if a.mode == "quarantine" {
		return false
	}
	now := store.NowMS()
	for _, b := range a.applied {
		if b.ExpiresAtMS > 0 && b.ExpiresAtMS <= now {
			continue
		}
		if b.IP.IsValid() && b.IP.Unmap() != ip {
			continue
		}
		m := pol.Match{Direction: b.Direction, Protocol: b.Protocol, RemotePort: b.Port, LocalPort: b.LocalPort}
		if m.Matches(c) {
			return false
		}
	}
	if d, ok := pol.Evaluate(a.groups, a.hostID, c, now); ok {
		return d.Action == "alert"
	}
	if _, ok := pol.Evaluate(a.rules, a.hostID, c, now); ok {
		return false
	}
	mode, storm := fw.SplitMode(a.mode)
	// В шторм новое с улицы режет шторм, а не обучение — вопроса не будет.
	if storm && c.Direction == "in" && !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)) {
		return false
	}
	return mode == "learn"
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
