package server

import (
	"crypto/tls"
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
var Version = "1.0.1"

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
}

func Init(cfg Config, password string) error {
	cfg = defaults(cfg)
	if password == "" {
		return fmt.Errorf("пароль adm задаётся при установке nmserver")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
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
		if err := store.PutSetting(tx, "samples_n", "30"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "samples_u", "d"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "flows_n", "90"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "flows_u", "d"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "hours_n", "12"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "hours_u", "mo"); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "db_max_gb", "2"); err != nil {
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
	addr := net.JoinHostPort(bindHost(cfg.ListenHost), strconv.Itoa(cfg.ListenPort))
	ln, err := tls.Listen("tcp", addr, tlsutil.ServerTLSConfig(bundle))
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("порт %s занят или недоступен: %w", addr, err)
	}
	s := &Server{cfg: cfg, st: st, bundle: bundle, ln: ln, startedMS: store.NowMS()}
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
	ln, err := tls.Listen("tcp", addr, tlsutil.ServerTLSConfig(s.bundle))
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
	_ = s.http.Close()
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	return s.st.Close()
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
	ag.DeliveryLane = batch.Lane
	if batch.Lane != "" && batch.Lane != "urgent" && batch.Lane != "history" && batch.Lane != "heartbeat" {
		http.Error(w, "invalid delivery lane", 400)
		return
	}
	now := store.NowMS()
	src, _, _ := net.SplitHostPort(r.RemoteAddr)
	var res ingest.Result
	err = s.st.Update(func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT trust_state FROM agents WHERE agent_id=?`, ag.ID).Scan(&ag.Trust); err != nil {
			return err
		}
		if ag.Trust == "revoked" {
			return fmt.Errorf("agent revoked")
		}
		if batch.PendingFrom != nil {
			if err := ingest.ConfirmQueue(tx, ag.ID, *batch.PendingFrom); err != nil {
				return err
			}
		}
		res = ingest.ApplyBatchWith(tx, ag, batch.Events, now, func(ev protocol.Event) error {
			if ag.Trust != "trusted" {
				return nil
			}
			if ev.Kind == "dns" {
				return refreshDNS(tx, ev)
			}
			return autoban(tx, ag, ev, now)
		})
		if res.Fatal != nil {
			return res.Fatal
		}
		if err := closeCoveredQuestions(tx, ag.HostID, now); err != nil {
			return err
		}
		var mon string
		if err := tx.QueryRow(`SELECT v FROM settings WHERE k='monitor_host_id'`).Scan(&mon); err == nil && mon != "" && mon == ag.HostID {
			if err := s.syncMonitorServiceRules(tx, mon); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`UPDATE agents SET last_src_ip=? WHERE agent_id=?`, src, ag.ID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	code := http.StatusOK
	if res.Err != "" {
		code = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(protocol.Ack{Ack: res.Ack, Error: res.Err})
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
