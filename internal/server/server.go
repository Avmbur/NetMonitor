package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/ingest"
	"netmonitor/internal/passwd"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

// Version — версия сборки; tools/build_release.py ставит сюда метку релиза.
var Version = "1.0.8"

type Config struct {
	ArtifactDir string
	DataDir     string
	ListenHost  string
	ListenPort  int
}

type Server struct {
	cfg       Config
	st        *store.Store
	bundle    *tlsutil.Bundle
	http      *http.Server
	ln        net.Listener
	mu        sync.Mutex
	startedMS int64
	sess      *sessStore
	// batchWait — сколько обычная телеметрия ждёт соседей, чтобы сесть в один коммит.
	// Ноль оставляет прежнее поведение: коммит сразу. Срочное и управление сюда не входят.
	batchWait time.Duration
	// agentStateMu spans batch commit and publication. Removal/rebinding waits
	// for both before changing the owner. Lock order: agentStateMu -> flushMu -> writer.
	agentStateMu sync.RWMutex
	flushMu      sync.Mutex
	// drops — ещё не сброшенные hits DROP и оперативная лента событий.
	drops dropBook
	// ssh — точные попытки SSH: скользящие 10 минут и отчёт.
	ssh       sshBook
	closeOnce sync.Once
	closeErr  error
	gate      *batchGate
	live      liveTable
	// serviceDisk — на диске только служебное. Потоки, пробы, сводки и квитанции
	// телеметрии туда не пишутся. Включается в Listen.
	session      string
	streams      map[string]*serviceStream // protected by agentStateMu; cursors by the batch gate
	pulseMu      sync.Mutex
	hostSeen     map[string]int64
	hostInv      map[string]protocol.HealthPayload
	collectFault map[string]string
	qMu          sync.Mutex
	qRep         map[string]int
	qSeen        map[string]int64
	qFlush       int64
	nameMu       sync.Mutex
	liveNames    map[string]serviceName
	knockMu      sync.Mutex
	knocks       map[string]formerAgent
	rebindTok    map[string]string
}

func Init(cfg Config, password string) error {
	cfg = defaults(cfg)
	if password == "" {
		return fmt.Errorf("пароль adm задаётся при установке nmserver")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if err := tlsutil.RestoreTrust(cfg.DataDir); err != nil {
		return err
	}
	st, err := store.OpenMonitor(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	hash, err := passwd.Hash(password)
	if err != nil {
		return err
	}
	bundle, err := tlsutil.LoadOrCreateCA(filepath.Join(cfg.DataDir, "tls"))
	if err != nil {
		return err
	}
	if err := bundle.WriteServer(nil, listenIPs(cfg.ListenHost)); err != nil {
		return err
	}
	if err := tlsutil.MirrorTrust(cfg.DataDir); err != nil {
		log.Printf("копия доверия: %v", err)
	}
	return st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "listen_host", cfg.ListenHost); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "listen_port", strconv.Itoa(cfg.ListenPort)); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "park_mode", "learn"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "adm_login", "adm"); err != nil {
			return err
		}
		var existing string
		err := tx.QueryRow(`SELECT v FROM settings WHERE k='adm_password'`).Scan(&existing)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && existing != "" {
			return fmt.Errorf("уже установлено: пароль adm уже задан")
		}
		if err := seedPolicy(tx); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "db_max_mb", "2048"); err != nil {
			return err
		}
		return store.PutSetting(tx, "adm_password", hash)
	})
}

func NewToken(dataDir string) (token string, err error) {
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return "", err
	}
	defer st.Close()
	token = idgen.Token()
	hash := idgen.TokenHash(token)
	now := store.NowMS()
	err = st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO enroll_tokens(token_hash, created_at_ms) VALUES(?,?)`, hash, now)
		return err
	})
	return token, err
}

// Endpoint is host:port saved at init; a reinstall keeps it.
func Endpoint(dataDir string) (string, error) {
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return "", err
	}
	defer st.Close()
	host, err := store.SettingDB(st.DB, "listen_host")
	if err != nil {
		return "", err
	}
	port, err := store.SettingDB(st.DB, "listen_port")
	if err != nil {
		return "", err
	}
	return endpoint(host, port), nil
}

func InstallCommand(dataDir, token string) (string, error) {
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return "", err
	}
	defer st.Close()
	host, err := store.SettingDB(st.DB, "listen_host")
	if err != nil {
		return "", err
	}
	port, err := store.SettingDB(st.DB, "listen_port")
	if err != nil {
		return "", err
	}
	ep := endpoint(host, port)
	if host == "0.0.0.0" || host == "::" || host == "" {
		return "", fmt.Errorf("задай достижимый --listen-host или получи команду в морде")
	}
	b, err := tlsutil.LoadOrCreateCA(filepath.Join(dataDir, "tls"))
	if err != nil {
		return "", err
	}
	pin, err := tlsutil.PublicKeyPin(b.ServerTLS.Certificate[0])
	if err != nil {
		return "", err
	}
	return installCmd(ep, pin, token), nil
}

func Listen(cfg Config) (*Server, error) {
	st, err := store.OpenMonitor(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if _, err := store.SettingDB(st.DB, "adm_password"); err != nil {
		st.Close()
		return nil, fmt.Errorf("сначала nmserver init: %w", err)
	}
	if cfg.ListenPort == 0 {
		v, err := store.SettingDB(st.DB, "listen_port")
		if err != nil {
			st.Close()
			return nil, err
		}
		cfg.ListenPort, err = strconv.Atoi(v)
		if err != nil || cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
			st.Close()
			return nil, fmt.Errorf("invalid stored listen port")
		}
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost, err = store.SettingDB(st.DB, "listen_host")
		if err != nil {
			st.Close()
			return nil, err
		}
	}
	if err := tlsutil.RestoreTrust(cfg.DataDir); err != nil {
		st.Close()
		return nil, err
	}
	ephemeral := cfg.ListenPort < 0
	cfg = defaults(cfg)
	if ephemeral {
		cfg.ListenPort = 0
		cfg.ListenHost = "127.0.0.1"
	}
	bundle, err := tlsutil.LoadOrCreateCA(filepath.Join(cfg.DataDir, "tls"))
	if err != nil {
		st.Close()
		return nil, err
	}
	if err := bundle.WriteServer(nil, listenIPs(cfg.ListenHost)); err != nil {
		st.Close()
		return nil, err
	}
	if err := tlsutil.MirrorTrust(cfg.DataDir); err != nil {
		log.Printf("копия доверия: %v", err)
	}
	addr := net.JoinHostPort(bindHost(cfg.ListenHost), strconv.Itoa(cfg.ListenPort))
	s := &Server{cfg: cfg, st: st, bundle: bundle, startedMS: store.NowMS(), batchWait: telemetryBatchWait, session: idgen.NewV7()}
	if err := s.dropUnusedRebind(); err != nil {
		st.Close()
		return nil, err
	}
	ln, err := s.listenTLS(addr)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("порт %s занят или недоступен: %w", addr, err)
	}
	s.ln = ln
	if err := s.ensureMonitorServiceRules(); err != nil {
		log.Printf("monitor service rules: %v", err)
	}
	if err := s.ensureUpdateRule(); err != nil {
		log.Printf("update service rule: %v", err)
	}
	if err := s.reconcileAlertsWithBans(); err != nil {
		log.Printf("сверка тревог с банами: %v", err)
	}
	if err := s.syncAttackGroup(); err != nil {
		log.Printf("группа атаки: %v", err)
	}
	if err := s.closeCapAlerts(); err != nil {
		log.Printf("старые тревоги потолка: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /v1/rebind", s.handleRebind)
	mux.HandleFunc("POST /v1/batch", s.handleBatch)
	mux.HandleFunc("GET /v1/poll", s.handlePoll)
	mux.HandleFunc("POST /v1/poll", s.handlePoll)
	mux.HandleFunc("POST /v1/uninstall-result", s.handleUninstallResult)
	mux.HandleFunc("POST /v1/update-result", s.handleUpdateResult)
	mux.HandleFunc("POST /v1/local-unblock", s.handleLocalUnblock)
	s.mountUI(mux)
	mux.HandleFunc("GET /install/{asset}", s.installAsset)
	s.http = &http.Server{
		Handler:      privateWeb(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     log.New(io.Discard, "", 0),
	}
	if err := s.ensureLive(); err != nil {
		log.Printf("живое состояние: %v", err)
	}
	return s, nil
}

func (s *Server) Serve() error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go s.expiryLoop(stop, done)
	parkDone := make(chan struct{})
	go s.parkLoop(stop, parkDone)
	defer func() { close(stop); <-done; <-parkDone }()
	for {
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		log.Printf("nmserver %s listen %s", Version, ln.Addr())
		err := s.http.Serve(ln)
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return err
		}
		s.mu.Lock()
		same := s.ln == ln
		s.mu.Unlock()
		if same {
			return err
		}
	}
}

func (s *Server) rebind(host string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт 1–65535")
	}
	if err := s.bundle.WriteServer(nil, listenIPs(host)); err != nil {
		return err
	}
	addr := net.JoinHostPort(bindHost(host), strconv.Itoa(port))
	ln, err := s.listenTLS(addr)
	if err != nil {
		return fmt.Errorf("порт занят")
	}
	s.mu.Lock()
	old := s.ln
	s.ln = ln
	s.cfg.ListenHost = host
	s.cfg.ListenPort = port
	s.mu.Unlock()
	if old != nil && old != ln {
		_ = old.Close()
	}
	return nil
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln.Addr().String()
}

func bumpTrusted(tx *sql.Tx) error {
	_, err := tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE trust_state='trusted'`)
	return err
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.finishClose() })
	return s.closeErr
}

func (s *Server) finishClose() error {
	if s.http != nil {
		_ = s.http.Close()
	}
	s.mu.Lock()
	ln := s.ln
	gate := s.gate
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	// Коммит приёма уже мог пройти, а публикация в очередь сброса — ещё нет.
	// Сначала дождаться этой публикации, и только потом сбрасывать очередь.
	if gate != nil {
		gate.quiesce()
	}
	var ferr error
	if s.st != nil {
		ferr = s.st.Update(func(tx *sql.Tx) error { return s.flushQuestionRepeats(tx, store.NowMS()) })
		if ferr == nil {
			ferr = s.flushSSHBrute(store.NowMS())
		}
	}
	var cerr error
	if s.st != nil {
		cerr = s.st.Close()
	}
	if ferr != nil {
		return ferr
	}
	return cerr
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req protocol.EnrollReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "token", http.StatusBadRequest)
		return
	}
	hash := idgen.TokenHash(req.Token)
	now := store.NowMS()
	agentID := idgen.NewV7()
	hostID := idgen.NewV7()
	certPEM, keyPEM, fp, err := s.bundle.IssueClient(agentID)
	if err != nil {
		http.Error(w, "cert", http.StatusInternalServerError)
		return
	}
	hostname := req.Hostname
	if hostname == "" {
		hostname = "pending"
	}
	src, _, _ := net.SplitHostPort(r.RemoteAddr)
	var boundFP string
	err = s.st.Update(func(tx *sql.Tx) error {
		var used sql.NullInt64
		err := tx.QueryRow(`SELECT used_at_ms FROM enroll_tokens WHERE token_hash=?`, hash).Scan(&used)
		if err == sql.ErrNoRows {
			return fmt.Errorf("неизвестный токен")
		}
		if err != nil {
			return err
		}
		if used.Valid {
			return fmt.Errorf("токен уже использован")
		}
		var bound sql.NullString
		if err := tx.QueryRow(`SELECT v FROM settings WHERE k=?`, "rebind:"+hash).Scan(&bound); err != nil && err != sql.ErrNoRows {
			return err
		}
		if bound.Valid {
			peer := ""
			if c := peerCert(r); c != nil {
				peer = tlsutil.Fingerprint(c.Raw)
			}
			if peer != bound.String {
				return fmt.Errorf("токен привязан к другому агенту")
			}
			if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, "rebind:"+hash); err != nil {
				return err
			}
			boundFP = bound.String
		}
		if _, err := tx.Exec(`UPDATE enroll_tokens SET used_at_ms=?, used_by_agent=? WHERE token_hash=?`, now, agentID, hash); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,?,?)`,
			hostID, hostname, now, now); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, display_name, boot_id, version, started_at_ms, first_seen_ms, last_src_ip)
			VALUES(?,?,?,?,?,?,?,?,?,?)`,
			agentID, hostID, fp, "pending", hostname, req.BootID, req.Version, now, now, src)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.dropFormer(boundFP)
	host, port := s.cfg.ListenHost, strconv.Itoa(s.cfg.ListenPort)
	if host == "0.0.0.0" || host == "::" || host == "" {
		if h, _, e := net.SplitHostPort(r.Host); e == nil {
			host = h
		}
	}
	writeJSON(w, protocol.EnrollRes{
		AgentID: agentID,
		HostID:  hostID,
		CAPEM:   string(s.bundle.CAPEM),
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		Monitor: "https://" + endpoint(host, port),
	})
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	ag, err := s.agentFromTLS(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	var batch protocol.Batch
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if f := batch.QuestionPendingFrom; f != nil {
		if *f < 1 {
			http.Error(w, "invalid question_pending_from", 400)
			return
		}
		for _, ev := range batch.Events {
			if !telemetryKind(ev.Kind) && ev.Seq < *f {
				http.Error(w, "service event below question_pending_from", 400)
				return
			}
		}
	}
	if batch.PendingFrom != nil {
		if *batch.PendingFrom < 1 {
			http.Error(w, "invalid pending_from", 400)
			return
		}
		for _, ev := range batch.Events {
			if ev.Seq < *batch.PendingFrom {
				http.Error(w, "event below pending_from", 400)
				return
			}
		}
	}
	if batch.AssignedThrough != nil {
		if *batch.AssignedThrough < 0 {
			http.Error(w, "invalid assigned_through", 400)
			return
		}
		for _, ev := range batch.Events {
			if ev.Seq > *batch.AssignedThrough {
				http.Error(w, "event above assigned_through", 400)
				return
			}
		}
	}
	if batch.Lane != "" && batch.Lane != "urgent" && batch.Lane != "history" && batch.Lane != "heartbeat" {
		http.Error(w, "invalid delivery lane", 400)
		return
	}
	if batch.Session != s.session {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, protocol.Ack{Session: s.session, Error: "session"})
		return
	}
	ag.DeliveryLane = batch.Lane
	now := store.NowMS()
	src, _, _ := net.SplitHostPort(r.RemoteAddr)
	job := &batchJob{
		ag:        ag,
		batch:     batch,
		now:       now,
		src:       src,
		ctx:       r.Context(),
		immediate: batchImmediate(batch),
		done:      make(chan struct{}),
	}
	s.enqueueBatch(job)
	select {
	case <-job.done:
	case <-r.Context().Done():
		return
	}
	if job.err != nil {
		http.Error(w, job.err.Error(), http.StatusInternalServerError)
		return
	}
	code := http.StatusOK
	if job.res.Err != "" {
		code = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	ack := protocol.Ack{Ack: job.res.Ack, Error: job.res.Err}
	{
		ack.Session = s.session
	}
	_ = json.NewEncoder(w).Encode(ack)
}

func (s *Server) applyAgentBatch(tx *sql.Tx, job *batchJob) (ingest.Result, error) {
	ag := job.ag
	var host string
	if err := tx.QueryRow(`SELECT trust_state,host_id FROM agents WHERE agent_id=?`, ag.ID).Scan(&ag.Trust, &host); err != nil {
		return ingest.Result{}, err
	}
	if host != ag.HostID {
		return ingest.Result{}, fmt.Errorf("agent host changed")
	}
	if ag.Trust == "revoked" {
		return ingest.Result{}, fmt.Errorf("agent revoked")
	}
	{
		return s.applyServiceBatch(tx, job)
	}

}

func defaults(cfg Config) Config {
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 8443
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = "0.0.0.0"
	}
	return cfg
}

func bindHost(h string) string {
	if h == "0.0.0.0" || h == "*" {
		return ""
	}
	return h
}

func endpoint(host, port string) string {
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " \t\"'\\$") {
		return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Session — номер сеанса боевого монитора. Пустая строка у тестового сервера без Listen.
func (s *Server) Session() string { return s.session }

func (s *Server) writePoll(w http.ResponseWriter, agentID string, res protocol.PollRes) {

	{
		res.Session = s.session
	}
	writeJSON(w, res)
}

func listenIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		return []net.IP{ip}
	}
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && !ip.IsUnspecified() {
			out = append(out, ip)
		}
	}
	return out
}
