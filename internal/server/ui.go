package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/idgen"

	"netmonitor/internal/passwd"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/web"
)

func (s *Server) mountUI(mux *http.ServeMux) {
	s.sess = newSess()
	mux.HandleFunc("POST /ui/api/never-block", s.needSess(s.handleNever))
	mux.HandleFunc("DELETE /ui/api/never-block/{id}", s.needSess(s.handleNever))
	static, _ := fs.Sub(web.FS, "static")
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("POST /ui/login", s.handleLogin)
	mux.HandleFunc("POST /ui/logout", s.handleLogout)
	mux.HandleFunc("GET /ui/api/state", s.needSess(s.handleState))
	mux.HandleFunc("POST /ui/api/agents/{id}/{action}", s.needSess(s.handleAgentAction))
	mux.HandleFunc("POST /ui/api/install", s.needSess(s.handleInstall))
	mux.HandleFunc("POST /ui/api/install-self", s.needSess(s.handleInstallSelf))
	mux.HandleFunc("POST /ui/api/settings", s.needSess(s.handleSaveSettings))
	mux.HandleFunc("POST /ui/api/block", s.needSess(s.handleUIBlock))
	mux.HandleFunc("POST /ui/api/unblock", s.needSess(s.handleUIUnblock))
	mux.HandleFunc("POST /ui/api/password", s.needSess(s.handlePassword))
	mux.HandleFunc("POST /ui/api/snapshot", s.needSess(s.handleSnapshot))
	mux.HandleFunc("POST /ui/api/db-clean", s.needSess(s.handleDBClean))
	mux.HandleFunc("POST /ui/api/remove-monitor", s.needSess(s.handleRemoveMonitor))
	mux.HandleFunc("POST /ui/api/rebind", s.needSess(s.handleRebindApprove))
	mux.HandleFunc("POST /ui/api/rule", s.needSess(s.handlePolicyRule))
	mux.HandleFunc("POST /ui/api/groups", s.needSess(s.handleGroups))
	mux.HandleFunc("POST /ui/api/alert", s.needSess(s.handleAlert))
	mux.HandleFunc("POST /ui/api/question", s.needSess(s.handleQuestion))
	mux.HandleFunc("GET /ui/api/reports", s.needSess(s.handleReports))
	mux.HandleFunc("GET /ui/api/policy.txt", s.needSess(s.handlePolicyExport))
	mux.HandleFunc("GET /ui/api/whois", s.needSess(s.handleWhois))
	mux.HandleFunc("GET /ui/api/dns", s.needSess(s.handleDNSLookup))
	mux.HandleFunc("GET /ui/api/update", s.needSess(s.handleUpdate))
	mux.HandleFunc("POST /ui/api/update", s.needSess(s.handleUpdate))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(web.FS, "static/index.html")
	if err != nil {
		http.Error(w, "ui", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	hash, err := store.SettingDB(s.st.DB, "adm_password")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if in.Login != "adm" || !passwd.Check(hash, in.Password) {
		http.Error(w, "неверный логин или пароль", 401)
		return
	}
	err = s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO audit_log(audit_id, at_ms, actor, action, object, src_ip) VALUES(?,?,?,?,?,?)`,
			idgen.NewV7(), store.NowMS(), "adm", "вход", "", r.RemoteAddr)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	id := s.sess.put("adm")
	setCookie(w, id)
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.del(cookieID(r))
	http.SetCookie(w, &http.Cookie{Name: "nm_sess", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server) needSess(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sess.get(cookieID(r)) {
			http.Error(w, "auth", 401)
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAgentTrust(w http.ResponseWriter, r *http.Request) { s.handleAgentAction(w, r) }

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	tok, err := NewToken(s.cfg.DataDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cmd, err := s.installationCommand(tok, r.Host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"command": cmd, "token": tok})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ListenHost    string          `json:"listen_host"`
		ListenPort    string          `json:"listen_port"`
		ParkMode      string          `json:"park_mode"`
		LAN           string          `json:"lan"`
		Starter       map[string]bool `json:"starter"`
		ObserveDocker *bool           `json:"observe_docker"`
		ScanPorts     int             `json:"scan_ports"`
		ScanWindowS   int             `json:"scan_window_s"`
		SoundAsk      *bool           `json:"sound_ask"`
		SoundAlert    *bool           `json:"sound_alert"`
		SoundAskS     *int            `json:"sound_ask_s"`
		SoundAlertS   *int            `json:"sound_alert_s"`
		DbMaxGb       int             `json:"db_max_gb"`
		DbMaxMb       int             `json:"db_max_mb"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	port := 0
	if in.ListenPort != "" {
		p, err := strconv.Atoi(in.ListenPort)
		if err != nil || p < 1 || p > 65535 {
			http.Error(w, "порт 1–65535", 400)
			return
		}
		port = p
	}
	switch in.ParkMode {
	case "", "learn", "allow", "block":
	default:
		http.Error(w, "режим", 400)
		return
	}
	if in.LAN != "" {
		for _, p := range strings.FieldsFunc(in.LAN, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := netip.ParsePrefix(strings.TrimSpace(p)); err != nil {
				http.Error(w, "LAN — CIDR", 400)
				return
			}
		}
	}
	curHost, _ := store.SettingDB(s.st.DB, "listen_host")
	curPortS, _ := store.SettingDB(s.st.DB, "listen_port")
	curPort, _ := strconv.Atoi(curPortS)
	host := strings.TrimSpace(in.ListenHost)
	needBind := (host != "" && host != curHost) || (port > 0 && port != curPort)
	if needBind {
		bindHost := host
		if bindHost == "" {
			bindHost = curHost
		}
		bindPort := port
		if bindPort == 0 {
			bindPort = curPort
		}
		if err := s.rebind(bindHost, bindPort); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
	}
	err := s.st.Update(func(tx *sql.Tx) error {
		if host != "" {
			if err := store.PutSetting(tx, "listen_host", host); err != nil {
				return err
			}
		}
		if in.ListenPort != "" {
			if err := store.PutSetting(tx, "listen_port", in.ListenPort); err != nil {
				return err
			}
		}
		if in.ParkMode != "" {
			if err := store.PutSetting(tx, "park_mode", in.ParkMode); err != nil {
				return err
			}
		}
		if in.LAN != "" {
			if err := store.PutSetting(tx, "lan", in.LAN); err != nil {
				return err
			}
		}
		if in.ObserveDocker != nil {
			v := "0"
			if *in.ObserveDocker {
				v = "1"
			}
			if err := store.PutSetting(tx, "observe_docker", v); err != nil {
				return err
			}
		}
		if in.ScanPorts > 0 {
			if err := store.PutSetting(tx, "scan_ports", strconv.Itoa(in.ScanPorts)); err != nil {
				return err
			}
		}
		if in.ScanWindowS > 0 {
			if err := store.PutSetting(tx, "scan_window_s", strconv.Itoa(in.ScanWindowS)); err != nil {
				return err
			}
		}
		if in.SoundAsk != nil {
			if err := store.PutSetting(tx, "sound_ask", bool01(*in.SoundAsk)); err != nil {
				return err
			}
		}
		if in.SoundAlert != nil {
			if err := store.PutSetting(tx, "sound_alert", bool01(*in.SoundAlert)); err != nil {
				return err
			}
		}
		if in.SoundAskS != nil {
			n := *in.SoundAskS
			if n < 1 {
				n = 1
			}
			if n > 3600 {
				n = 3600
			}
			if err := store.PutSetting(tx, "sound_ask_s", strconv.Itoa(n)); err != nil {
				return err
			}
		}
		if in.SoundAlertS != nil {
			n := *in.SoundAlertS
			if n < 1 {
				n = 1
			}
			if n > 3600 {
				n = 3600
			}
			if err := store.PutSetting(tx, "sound_alert_s", strconv.Itoa(n)); err != nil {
				return err
			}
		}
		if in.DbMaxMb > 0 {
			n := in.DbMaxMb
			if n < 64 {
				n = 64
			}
			if n > 99<<10 {
				n = 99 << 10
			}
			if err := store.PutSetting(tx, "db_max_mb", strconv.Itoa(n)); err != nil {
				return err
			}
		} else if in.DbMaxGb > 0 {
			n := in.DbMaxGb
			if n > 99 {
				n = 99
			}
			if err := store.PutSetting(tx, "db_max_mb", strconv.Itoa(n<<10)); err != nil {
				return err
			}
		}
		if in.Starter != nil {
			if err := applyStarter(tx, in.Starter); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), "adm", "сохранил настройки", ""); err != nil {
			return err
		}
		if in.ParkMode != "" || in.LAN != "" || in.Starter != nil || in.ObserveDocker != nil || in.ScanPorts > 0 || in.ScanWindowS > 0 {
			if err := bumpTrusted(tx); err != nil {
				return err
			}
		}
		if in.LAN != "" || in.ListenPort != "" {
			var mon string
			if err := tx.QueryRow(`SELECT v FROM settings WHERE k='monitor_host_id'`).Scan(&mon); err == nil && mon != "" {
				if err := s.syncMonitorServiceRules(tx, mon); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

func bool01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

type banInput struct {
	ID        string          `json:"id"`
	IP        string          `json:"ip"`
	Protocol  string          `json:"proto"`
	Direction string          `json:"direction"`
	Port      int             `json:"port"`
	LocalPort int             `json:"local_port"`
	Confirm   bool            `json:"confirm_local_port"`
	TTL       string          `json:"ttl"`
	UntilMS   int64           `json:"until_ms"`
	Forever   bool            `json:"forever"`
	Hosts     json.RawMessage `json:"hosts"`
	Except    []string        `json:"except"`
	Reason    string          `json:"reason"`
}

func banFromInput(in banInput, now int64) (banSpec, error) {
	b := banSpec{
		ID: strings.TrimSpace(in.ID), RemoteIP: strings.TrimSpace(in.IP),
		Protocol: in.Protocol, Direction: in.Direction, Port: in.Port, LocalPort: in.LocalPort,
		Except: in.Except, Reason: strings.TrimSpace(in.Reason), Source: "manual", CreatedBy: "adm",
	}
	if b.Reason == "" {
		b.Reason = "ручной"
	}
	if b.Direction == "" {
		b.Direction = "both"
	}
	var err error
	if b.Hosts, err = parseScope(in.Hosts, ""); err != nil {
		return b, err
	}
	if in.UntilMS < 0 {
		return b, fmt.Errorf("неверный срок бана")
	}
	switch {
	case in.Forever:
	case in.UntilMS > 0:
		if in.UntilMS <= now {
			return b, fmt.Errorf("срок бана уже прошёл")
		}
		b.ExpiresAt = in.UntilMS
	case in.TTL == "forever":
	default:
		ttl := time.Hour
		if in.TTL != "" {
			var err error
			ttl, err = time.ParseDuration(in.TTL)
			if err != nil || ttl <= 0 || ttl.Milliseconds() == 0 {
				return b, fmt.Errorf("неверная длительность бана")
			}
		}
		b.ExpiresAt = now + ttl.Milliseconds()
	}
	return b, validateBan(b, in.Confirm)
}

// One path for create, extend and scope change: the saved ban is the ban that
// agents receive, and its confirmation starts again after every change.
func (s *Server) handleUIBlock(w http.ResponseWriter, r *http.Request) {
	var in banInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	now := store.NowMS()
	b, err := banFromInput(in, now)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	action := "забанил"
	if b.ID != "" {
		action = "изменил бан"
	}
	var id string
	err = s.st.Update(func(tx *sql.Tx) error {
		for _, h := range append(append([]string{}, b.Hosts...), b.Except...) {
			var n int
			if err := tx.QueryRow("SELECT count(*) FROM hosts WHERE host_id=?", h).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("неизвестный сервер")
			}
		}
		if b.ID != "" {
			old, err := readBan(tx, b.ID)
			if err != nil {
				return err
			}
			b.Source, b.CreatedBy = old.Source, old.CreatedBy
			if err := validateBan(b, in.Confirm); err != nil {
				return err
			}
		}
		var err error
		if id, err = writeBan(tx, b, now); err != nil {
			return err
		}
		b.ID = id
		return auditBan(tx, "adm", action, b, now)
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

// Lifting one ban by id must not touch another ban on the same address.
func (s *Server) handleUIUnblock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in.ID == "" {
		http.Error(w, "нужен id бана", 400)
		return
	}
	err := s.st.Update(func(tx *sql.Tx) error { return removeBan(tx, in.ID, "adm", store.NowMS()) })
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	hash, err := store.SettingDB(s.st.DB, "adm_password")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !passwd.Check(hash, in.Old) {
		http.Error(w, "неверный пароль", 401)
		return
	}
	if in.New == "" {
		http.Error(w, "пустой", 400)
		return
	}
	nh, err := passwd.Hash(in.New)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "adm_password", nh); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), "adm", "сменил пароль", "")
		return err
	}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	dest, err := s.takeSnapshot()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(dest))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, dest)
		return
	}
	writeJSON(w, map[string]string{"ok": "1", "file": filepath.Base(dest)})
}

// Тяжёлые чтения морды (состояние, отчёты) идут не больше четырёх разом:
// каждое может держать несколько соединений, пул монитора — 64 (store).
var uiReadSlots = make(chan struct{}, 4)

func uiReadSlot(r *http.Request) (release func(), ok bool) {
	select {
	case uiReadSlots <- struct{}{}:
		return func() { <-uiReadSlots }, true
	case <-r.Context().Done():
		return nil, false
	}
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	release, ok := uiReadSlot(r)
	if !ok {
		return
	}
	defer release()
	q := r.URL.Query()
	st := s.uiStateQ(stateQuery{
		Server:   q.Get("server"),
		Section:  q.Get("section"),
		Addr:     q.Get("addr"),
		Action:   q.Get("action"),
		Who:      q.Get("who"),
		Process:  q.Get("process"),
		FromMS:   parseMS(q.Get("from_ms")),
		ToMS:     parseMS(q.Get("to_ms")),
		After:    parseMS(q.Get("after")),
		BanView:  q.Get("ban_view"),
		BanIP:    q.Get("ban_ip"),
		BanSince: parseMS(q.Get("ban_since")),
		BanID:    q.Get("ban_id"),
	})
	if st.err != nil {
		http.Error(w, st.err.Error(), 500)
		return
	}
	writeJSON(w, st)
}

func parseMS(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

type stateQuery struct {
	Server, Section, Addr, Action, Who, Process string
	FromMS, ToMS, After                         int64
	BanView, BanIP, BanID                       string
	BanSince                                    int64
}

type uiState struct {
	err        error
	HasTrusted bool              `json:"has_trusted"`
	Now        uiNow             `json:"now"`
	Servers    []uiServer        `json:"servers"`
	Agents     []uiAgent         `json:"agents"`
	Flows      []uiFlow          `json:"flows,omitempty"`
	History    []uiFlow          `json:"history,omitempty"`
	Bans       []uiBan           `json:"bans,omitempty"`
	Never      []uiNever         `json:"never_block,omitempty"`
	Audit      []uiAudit         `json:"audit,omitempty"`
	Groups     []uiGroup         `json:"groups,omitempty"`
	Questions  []uiQuestion      `json:"questions"`
	Rules      []policy.Rule     `json:"rules,omitempty"`
	Alerts     []uiAlert         `json:"alerts"`
	Reports    []uiReportMeta    `json:"reports,omitempty"`
	HostNames  map[string]string `json:"host_names,omitempty"`
	Settings   map[string]string `json:"settings"`
	Starter    map[string]bool   `json:"starter,omitempty"`
	Loaded     []string          `json:"loaded,omitempty"`
	Monitor    map[string]any    `json:"monitor"`
	Knocks     []formerAgent     `json:"knocks,omitempty"`
	User       string            `json:"user,omitempty"`
}

type uiQuestion struct {
	ID          string `json:"id"`
	HostID      string `json:"host_id"`
	VM          string `json:"vm"`
	Proc        string `json:"proc"`
	Container   string `json:"container,omitempty"`
	ContainerIP string `json:"container_ip,omitempty"`
	Port        int    `json:"port"`
	Path        string `json:"path"`
	Dir         string `json:"dir"`
	Proto       string `json:"proto"`
	Dest        string `json:"dest"`
	Peer        string `json:"peer"`
	Names       string `json:"names"`
	Repeats     int    `json:"repeats"`
	At          string `json:"at"`
	Inbound     bool   `json:"inbound"`
}

type uiBan struct {
	ID        string          `json:"id"`
	IP        string          `json:"ip"`
	Target    string          `json:"target"`
	State     string          `json:"state"`
	Until     string          `json:"until"`
	UntilMS   int64           `json:"until_ms"`
	Reason    string          `json:"reason"`
	Source    string          `json:"source"`
	Protocol  string          `json:"proto"`
	Direction string          `json:"direction"`
	Port      int             `json:"port"`
	LocalPort int             `json:"local_port"`
	Hosts     json.RawMessage `json:"hosts"`
	Except    []string        `json:"except"`
	Applied   int             `json:"applied"`
	Total     int             `json:"total"`
	Persist   bool            `json:"persist"`
	Paused    []string        `json:"paused,omitempty"`
	Missed    []string        `json:"missed,omitempty"`
	CreatedMS int64           `json:"created_ms,omitempty"`
	RemovedMS int64           `json:"removed_ms,omitempty"`
}

type uiAudit struct {
	When   string `json:"when"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Object string `json:"object"`
}

type uiNow struct {
	Flows   int `json:"flows"`
	Allowed int `json:"allowed"`
	Blocked int `json:"blocked"`
	Pending int `json:"pending"`
}

type uiServer struct {
	Addresses []string              `json:"addresses"`
	OpenPorts *int                  `json:"open_ports"`
	Listeners []protocol.ListenPort `json:"listeners,omitempty"`
	Online    bool                  `json:"online"`
	HostID    string                `json:"host_id"`
	Name      string                `json:"name"`
	Trust     string                `json:"trust"`
	Monitor   bool                  `json:"monitor,omitempty"`
	CPU       *int                  `json:"cpu_pct,omitempty"`
	RAM       *int                  `json:"ram_pct,omitempty"`
	Disk      *int                  `json:"disk_pct,omitempty"`
	Rx24      int64                 `json:"rx24"`
	Tx24      int64                 `json:"tx24"`
}

type uiAgent struct {
	HostID     string                `json:"host_id"`
	Control    hostControl           `json:"control"`
	Online     bool                  `json:"online"`
	Last       int64                 `json:"last_seen_ms"`
	ScopeNote  string                `json:"scope_note"`
	IPv6Seen   bool                  `json:"ipv6_seen"`
	PolicyRev  int64                 `json:"policy_rev"`
	FWBackend  string                `json:"fw_backend"`
	FW         *protocol.ApplyStatus `json:"fw"`
	AgentID    string                `json:"agent_id"`
	Name       string                `json:"name"`
	Trust      string                `json:"trust"`
	Monitor    bool                  `json:"monitor,omitempty"`
	TrustLabel string                `json:"trust_label"`
	Key        string                `json:"key"`
	Version    string                `json:"version"`
	Queue      int64                 `json:"queue"`
	ResumeHost string                `json:"resume_host,omitempty"`
	ResumeName string                `json:"resume_name,omitempty"`
	// Removing — последняя команда снятия: wait — ждём машину, old — агент
	// старой сборки снимать себя не умеет.
	Removing     string `json:"removing,omitempty"`
	RemovalError string `json:"removalError,omitempty"`
	CollectFault string `json:"collect_fault,omitempty"`
	Stopped      bool   `json:"stopped,omitempty"`
}

type uiAlert struct {
	ID         string `json:"id"`
	Rule       string `json:"rule"`
	HostID     string `json:"host_id"`
	VM         string `json:"vm"`
	At         string `json:"at"`
	OpenedMS   int64  `json:"opened_ms"`
	Text       string `json:"text"`
	Addr       string `json:"addr,omitempty"`
	Hist       bool   `json:"hist"`
	Kind       string `json:"kind"`
	Hint       string `json:"hint,omitempty"`
	State      string `json:"state"` // red — активна, yellow — снята и не видел, green — видел
	Seen       bool   `json:"seen"`
	Closed     string `json:"closed,omitempty"`
	ClosedBy   string `json:"closed_by,omitempty"`
	CloseText  string `json:"close_text,omitempty"`
	IPTables   bool   `json:"iptables,omitempty"`
	BanID      string `json:"ban_id,omitempty"`
	BanState   string `json:"ban_state,omitempty"`
	BanAt      string `json:"ban_at,omitempty"`
	BanUntil   string `json:"ban_until,omitempty"`
	BanGone    string `json:"ban_gone,omitempty"`
	BanScope   string `json:"ban_scope,omitempty"`
	BanUntilMS int64  `json:"ban_until_ms,omitempty"`
}

type uiFlow struct {
	FlowUID     string `json:"flow_uid"`
	Ended       *int64 `json:"ended_at_ms"`
	Incomplete  bool   `json:"incomplete"`
	When        string `json:"when"`
	HostID      string `json:"host_id"`
	Server      string `json:"server"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	Proc        string `json:"proc"`
	Container   string `json:"container,omitempty"`
	ContainerIP string `json:"container_ip,omitempty"`
	Port        int    `json:"port"`
	Path        string `json:"path"`
	Addr        string `json:"addr"`
	Peer        string `json:"peer"`
	DNS         string `json:"dns"`
	Rx          int64  `json:"rx"`
	Tx          int64  `json:"tx"`
	Rate        int64  `json:"rate"`
	RateKnown   bool   `json:"rate_known"`
	Rule        string `json:"rule"`
	State       string `json:"state"`
	Tip         string `json:"tip"`
}

func sectionIn(section string, names ...string) bool {
	if section == "" {
		return true
	}
	for _, n := range names {
		if section == n {
			return true
		}
	}
	return false
}

func (s *Server) uiState(serverFilter, section string) uiState {
	return s.uiStateQ(stateQuery{Server: serverFilter, Section: section})
}

func (s *Server) uiStateQ(q stateQuery) (st uiState) {
	db := &checkedRead{db: s.st.DB}
	defer func() { st.err = db.err }()
	serverFilter, section := q.Server, q.Section
	st = uiState{Settings: map[string]string{}, Monitor: map[string]any{}, User: "adm"}
	st.Settings["listen_host"] = db.setting("listen_host")
	st.Settings["listen_port"] = db.setting("listen_port")
	st.Settings["park_mode"] = db.setting("park_mode")
	st.Settings["lan"] = db.setting("lan")
	st.Settings["sound_ask"] = db.setting("sound_ask")
	st.Settings["sound_alert"] = db.setting("sound_alert")
	st.Settings["sound_ask_s"] = db.setting("sound_ask_s")
	st.Settings["sound_alert_s"] = db.setting("sound_alert_s")
	st.Settings["db_max_gb"] = db.setting("db_max_gb")
	st.Settings["db_max_mb"] = db.setting("db_max_mb")
	if st.Settings["lan"] == "" {
		st.Settings["lan"] = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
	}
	st.Settings["snap_at"] = db.setting("snap_at")
	if sectionIn(section, "settings") {
		st.Starter = starterState(db.db)
	}
	s.fillMonitor(&st)
	st.HostNames = hostNames(db.db)

	rows, err := db.Query(`SELECT a.agent_id, a.host_id, COALESCE(a.display_name,h.hostname,''), a.trust_state, a.cert_fingerprint, a.policy_rev, COALESCE(a.fw_backend,'unknown'), COALESCE(fw.v,''),COALESCE(a.scope_note,''),a.ipv6_seen,COALESCE(h.last_seen_ms,0),COALESCE(a.version,''),COALESCE(a.last_src_ip,'')
		FROM agents a LEFT JOIN hosts h ON h.host_id=a.host_id LEFT JOIN settings fw ON fw.k='fw_status:'||a.agent_id ORDER BY a.first_seen_ms`)
	if err == nil {
		for rows.Next() {
			var ag uiAgent
			var hostID, fp, fwJSON, lastIP string
			_ = rows.Scan(&ag.AgentID, &hostID, &ag.Name, &ag.Trust, &fp, &ag.PolicyRev, &ag.FWBackend, &fwJSON, &ag.ScopeNote, &ag.IPv6Seen, &ag.Last, &ag.Version, &lastIP)
			ag.HostID = hostID
			ag.Online = ag.Trust == "trusted" && ag.Last > store.NowMS()-60000
			s.applyPulse(&ag)
			if inv := db.setting("inventory:" + hostID); inv != "" {
				var h protocol.HealthPayload
				if json.Unmarshal([]byte(inv), &h) == nil && h.QueueBytes != nil {
					ag.Queue = *h.QueueBytes
				}
			}
			s.applyPulse(&ag)
			if fwJSON != "" {
				db.record(json.Unmarshal([]byte(fwJSON), &ag.FW))
			}
			ag.TrustLabel = map[string]string{"pending": "ожидает", "trusted": "онлайн", "quarantined": "карантин", "revoked": "отозван"}[ag.Trust]
			if ag.Trust == "pending" {
				if hid, hname := peekOrphanHost(s.st.DB, ag.Name, lastIP, hostID); hid != "" {
					ag.ResumeHost = hid
					ag.ResumeName = hname
				}
			}
			if ag.Trust == "trusted" && !ag.Online {
				ag.TrustLabel = "нет данных"
			}
			if ag.TrustLabel == "" {
				ag.TrustLabel = ag.Trust
			}
			if len(fp) > 10 {
				ag.Key = fp[:6] + "…" + fp[len(fp)-2:]
			} else {
				ag.Key = fp
			}
			st.Agents = append(st.Agents, ag)
			if ag.Trust == "trusted" {
				st.Servers = append(st.Servers, uiServer{HostID: hostID, Name: ag.Name, Trust: ag.Trust, Online: ag.Online})
			}
			if ag.Trust == "trusted" {
				st.HasTrusted = true
			}
		}
		rows.Close()
	}
	mon, _, _ := s.findMonitorAgent()
	for i := range st.Agents {
		c, err := readControl(s.st.DB, st.Agents[i].HostID)
		db.record(err)
		st.Agents[i].Control = c
		var open int
		var result string
		err = s.st.DB.QueryRow(`SELECT acked_at_ms IS NULL, COALESCE(result,''),COALESCE(error,'') FROM commands WHERE agent_id=? AND kind='uninstall' ORDER BY created_at_ms DESC LIMIT 1`, st.Agents[i].AgentID).Scan(&open, &result, &st.Agents[i].RemovalError)
		if err != sql.ErrNoRows {
			db.record(err)
		}
		if err == nil && result == "remove_error" {
			st.Agents[i].Removing = "error"
		} else if err == nil && open == 1 {
			st.Agents[i].Removing = "wait"
		} else if err == nil && result == "unsupported" {
			st.Agents[i].Removing = "old"
		}
		if mon.HostID != "" && st.Agents[i].HostID == mon.HostID {
			st.Agents[i].Monitor = true
			st.Agents[i].Name = monitorAgentName
		}
		if settingValue(db.db, "agent_stopped:"+st.Agents[i].HostID, "") != "" {
			st.Agents[i].Stopped = true
			st.Agents[i].Online = false
		}
	}
	for i := range st.Servers {
		if mon.HostID != "" && st.Servers[i].HostID == mon.HostID {
			st.Servers[i].Monitor = true
			st.Servers[i].Name = monitorAgentName
		}
		if !sectionIn(section, "activity") {
			continue
		}
		var inventory string
		err := db.QueryRow("SELECT COALESCE((SELECT v FROM settings WHERE k=?),\"\")", "inventory:"+st.Servers[i].HostID).Scan(&inventory)
		if err == nil && inventory != "" {
			var h protocol.HealthPayload
			db.record(json.Unmarshal([]byte(inventory), &h))
			st.Servers[i].Addresses = h.Addresses
			st.Servers[i].OpenPorts = h.OpenPorts
			st.Servers[i].Listeners = h.Listeners
			st.Servers[i].CPU = h.CPUPct
			st.Servers[i].RAM = h.RAMPct
			st.Servers[i].Disk = h.DiskPct
		}
		s.applyServerPulse(&st.Servers[i])
	}
	hostFilter := serverFilter != "" && serverFilter != "all" && section != "settings"
	countFilter := hostFilter && section != "log"
	// Ж1: живой список и счётчик открытых — из памяти.
	// Ж4: плитка DROP — диск и ещё не сброшенные hits. Лента DROP — из памяти.
	n, liveRows, rates, liveErr := s.liveActivity(serverFilter, countFilter, sectionIn(section, "activity"))
	if liveErr != nil {
		db.record(liveErr)
	}
	st.Now.Flows = n
	since := store.NowMS() - 86400000
	pendQ := `SELECT COUNT(*) FROM learn_questions WHERE status='open' AND host_id IN (SELECT host_id FROM agents WHERE trust_state='trusted')`
	if countFilter {
		pendQ += ` AND host_id=?`
		_ = db.QueryRow(pendQ, serverFilter).Scan(&st.Now.Pending)
	} else {
		_ = db.QueryRow(pendQ).Scan(&st.Now.Pending)
	}
	st.Now.Blocked = s.blockedNow(db, since, serverFilter, countFilter)
	st.Now.Allowed = st.Now.Flows

	if sectionIn(section, "activity") {
		st.Flows = finishFlows(db, liveRows, false, s.lookupDNS)
		stampLiveRates(st.Flows, rates)
		if st.Flows == nil {
			st.Flows = []uiFlow{}
		}
	}
	if sectionIn(section, "log") {
		st.History = s.readUIFirewall(db, serverFilter, hostFilter)
		sort.SliceStable(st.History, func(i, j int) bool { return st.History[i].When > st.History[j].When })
		if st.History == nil {
			st.History = []uiFlow{}
		}
		st.Audit = readUIAudit(db, q)
		if st.Audit == nil {
			st.Audit = []uiAudit{}
		}
	}
	if sectionIn(section, "policy") {
		st.Bans = s.listBans(db, banListFilter{View: q.BanView, IP: q.BanIP, Since: q.BanSince, ID: q.BanID})
		if st.Bans == nil {
			st.Bans = []uiBan{}
		}
		nr, err := db.Query("SELECT id,cidr,COALESCE(reason,'') FROM never_block ORDER BY created_at_ms,id")
		if err == nil {
			for nr.Next() {
				var n uiNever
				if nr.Scan(&n.ID, &n.Addr, &n.Note) == nil {
					st.Never = append(st.Never, n)
				}
			}
			nr.Close()
		}
		monitorHost := st.Settings["listen_host"]
		if monitorHost == "" || monitorHost == "0.0.0.0" || monitorHost == "::" {
			monitorHost = "монитор из конфига агента"
		}
		st.Never = append(st.Never, uiNever{ID: "monitor", Addr: monitorHost, Note: "адрес монитора из конфига агента", Locked: true})
		st.Groups = s.listGroups(db)
		if st.Groups == nil {
			st.Groups = []uiGroup{}
		}
		st.Rules = s.listPolicyRules(db)
		if st.Rules == nil {
			st.Rules = []policy.Rule{}
		}
	}
	st.Questions = s.listQuestions(db, serverFilter, hostFilter)
	if st.Questions == nil {
		st.Questions = []uiQuestion{}
	}
	st.Alerts = listUIAlerts(db)
	if st.Alerts == nil {
		st.Alerts = []uiAlert{}
	}
	if sectionIn(section, "reports") {
		st.Reports = s.visibleReports()
	}
	st.Loaded = []string{"servers", "agents", "alerts", "questions"}
	if sectionIn(section, "activity") {
		st.Loaded = append(st.Loaded, "flows")
	}
	if sectionIn(section, "log") {
		st.Loaded = append(st.Loaded, "history", "audit")
	}
	if sectionIn(section, "policy") {
		st.Loaded = append(st.Loaded, "bans", "never_block", "groups", "rules")
	}
	if sectionIn(section, "reports") {
		st.Loaded = append(st.Loaded, "reports")
	}
	if sectionIn(section, "settings") {
		st.Loaded = append(st.Loaded, "starter")
	}
	if !st.HasTrusted {
		st.Now = uiNow{}
		st.Flows = nil
		st.History = nil
		st.Questions = nil
	}
	return st
}

func (s *Server) listQuestions(db *checkedRead, serverFilter string, hostFilter bool) []uiQuestion {
	q := `SELECT q.question_id, q.host_id, COALESCE(h.hostname,''), COALESCE(q.proc_comm,''), COALESCE(q.proc_path,''), COALESCE(q.container,''),
		COALESCE(q.direction,''), COALESCE(q.protocol,''), COALESCE(q.remote_ip,''), CASE WHEN q.direction='in' THEN COALESCE(q.local_port,0) ELSE COALESCE(q.remote_port,0) END,
		COALESCE(q.dns_name,''), q.repeats, q.opened_at_ms, q.dedup_key
		FROM learn_questions q LEFT JOIN hosts h ON h.host_id=q.host_id
		WHERE q.status='open' AND q.host_id IN (SELECT host_id FROM agents WHERE trust_state='trusted')`
	args := []any{}
	if hostFilter {
		q += ` AND q.host_id=?`
		args = append(args, serverFilter)
	}
	q += ` ORDER BY q.last_seen_ms DESC LIMIT 80`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []uiQuestion
	for rows.Next() {
		var u uiQuestion
		var rport, opened int64
		var dedupKey string
		if err := rows.Scan(&u.ID, &u.HostID, &u.VM, &u.Proc, &u.Path, &u.Container, &u.Dir, &u.Proto, &u.Peer, &rport, &u.Names, &u.Repeats, &opened, &dedupKey); err != nil {
			continue
		}
		s.qMu.Lock()
		u.Repeats = max(u.Repeats, s.qRep[u.ID])
		s.qMu.Unlock()
		u.VM = u.HostID
		u.Port = int(rport)
		if _, ip, ok := strings.Cut(dedupKey, "|\u25a3"); ok {
			if addr, err := netip.ParseAddr(ip); err == nil {
				u.ContainerIP = addr.Unmap().String()
			}
		}
		if u.ContainerIP != "" || u.Container != "" {
			u.Proc, u.Path = "", ""
		}
		u.Proc = displayProc(u.Proc, u.Path)
		if u.Proc == "" {
			u.Proc = "—"
		}
		u.Dest = u.Peer
		if rport > 0 {
			if u.Dir == "in" {
				u.Dest = fmt.Sprintf(":%d ← %s", rport, u.Peer)
			} else {
				u.Dest += fmt.Sprintf(":%d", rport)
			}
		}
		u.At = fmtMS(opened)
		u.Inbound = u.Dir == "in"
		if u.Names == "" {
			u.Names = s.lookupDNS(db, u.HostID, u.Peer, u.Proto, int(rport))
		}
		out = append(out, u)
	}
	return out
}

func procNameFromPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.Contains(path, "/apt/methods/") {
		return "apt"
	}
	for _, part := range strings.Fields(path) {
		if strings.HasPrefix(part, "cgroup=") || strings.HasPrefix(part, "uid=") {
			continue
		}
		part = strings.ReplaceAll(part, "\\", "/")
		if i := strings.LastIndex(part, "/"); i >= 0 {
			part = part[i+1:]
		}
		if plausibleProc(part) {
			return part
		}
	}
	return ""
}

func plausibleProc(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name == "—" || name == "-" || name == "ядро" {
		return false
	}
	switch strings.ToLower(name) {
	case "tcp", "udp", "icmp", "icmpv6", "ssl", "tls":
		return false
	}
	if looksHostname(name) {
		return false
	}
	if strings.HasPrefix(name, "session-") || strings.HasSuffix(name, ".scope") || strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".slice") {
		return false
	}
	return true
}

func looksHostname(name string) bool {
	i := strings.LastIndex(name, ".")
	if i <= 0 || i == len(name)-1 {
		return false
	}
	for _, c := range name[i+1:] {
		if c < '0' || c > '9' {
			return true
		}
	}
	return false
}

func displayProc(comm, path string) string {
	fromPath := procNameFromPath(path)
	if fromPath != "" {
		return fromPath
	}
	if plausibleProc(comm) {
		return strings.TrimSpace(comm)
	}
	return ""
}

func lookupDNS(db *checkedRead, host, ip, proto string, port int) string {
	if ip == "" {
		return ""
	}
	var name string
	err := db.db.QueryRow(`SELECT name FROM dns_seen WHERE ip=? ORDER BY CASE WHEN host_id=? THEN 0 ELSE 1 END, last_seen_ms DESC LIMIT 1`, ip, host).Scan(&name)
	if err == nil && name != "" {
		return name
	}
	return ntpUbuntuName(ip, proto, port)
}

func ntpUbuntuName(ip, proto string, port int) string {
	if proto != "udp" || port != 123 {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	for _, cidr := range []string{"185.125.190.0/24", "91.189.91.0/24"} {
		p := netip.MustParsePrefix(cidr)
		if p.Contains(addr) {
			return "ntp.ubuntu.com"
		}
	}
	return ""
}

func fmtMS(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).In(time.Local).Format("02.01.2006 15:04:05")
}

func asInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

type flowRow struct {
	f                            uiFlow
	origin, replySrc             string
	lip, rip, state, cg, flowDNS string
	lp, rp, end, puid            sql.NullInt64
	ob, rb, last                 int64
	reply                        int
}

func finishFlows(db *checkedRead, raw []flowRow, withRates bool, names ...func(*checkedRead, string, string, string, int) string) []uiFlow {
	nameLookup := lookupDNS
	if len(names) > 0 {
		nameLookup = names[0]
	}
	park := db.setting("park_mode")
	never := neverPrefixes(db.db)
	decided := map[string]hostDecision{}
	now := store.NowMS()
	var out []uiFlow
	for _, r := range raw {
		f := r.f
		lip, rip, state, cg, flowDNS := r.lip, r.rip, r.state, r.cg, r.flowDNS
		lp, rp, end, puid := r.lp, r.rp, r.end, r.puid
		ob, rb, last, reply := r.ob, r.rb, r.last, r.reply
		f.Port = int(rp.Int64)
		if f.Direction == "in" {
			f.Port = int(lp.Int64)
		}
		if (r.origin == "docker" || f.Container != "") && f.Direction != "bridge" {
			f.ContainerIP = lip
			if f.Direction == "in" && r.replySrc != "" {
				f.ContainerIP = r.replySrc
			}
			f.Proc, f.Path, cg, puid = "", "", "", sql.NullInt64{}
		}
		var uid *int
		if puid.Valid {
			n := int(puid.Int64)
			uid = &n
		}
		if ident := policy.FormatIdentity(f.Path, uid, cg); ident != "" {
			f.Path = ident
		}
		f.Peer = rip
		f.Local = flowEndpoint(lip, lp)
		f.Remote = flowEndpoint(rip, rp)
		if f.Direction == "in" {
			port := "—"
			if lp.Valid {
				port = ":" + strconv.FormatInt(lp.Int64, 10)
			}
			f.Addr = port + " ← " + f.Remote
			f.Rx, f.Tx = ob, rb
		} else {
			f.Addr = "→ " + f.Remote
			f.Rx, f.Tx = rb, ob
		}
		f.Proc = displayProc(f.Proc, f.Path)
		if f.Proc == "" {
			f.Proc = "—"
		}
		rport := 0
		if rp.Valid {
			rport = int(rp.Int64)
		}
		f.DNS = nameLookup(db, f.HostID, rip, f.Protocol, rport)
		if f.DNS == "" {
			f.DNS = flowDNS
		}
		f.State = "open"
		if f.Protocol == "tcp" {
			switch state {
			case "CLOSE", "TIME_WAIT", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK":
				f.State = "closing"
			case "SYN_SENT", "SYN_RECV":
				f.State = "waiting"
			}
		}
		f.Tip = state
		if reply == 0 {
			f.Tip += "; ответа не было"
		}
		if end.Valid {
			n := end.Int64
			f.Ended = &n
			f.State = "closed"
		} else if last < store.NowMS()-60000 {
			f.State = "stale"
			f.Tip += "; нет свежих данных"
		}
		if f.Incomplete {
			f.Tip += "; начало наблюдения неполное"
		}
		d, ok := decided[f.HostID]
		if !ok {
			if hd, e := loadHostDecision(db.db, f.HostID, never, park); e != nil {
				db.record(e)
			} else {
				decided[f.HostID] = hd
				d, ok = hd, true
			}
		}
		if ok {
			lpn, rpn := 0, 0
			if lp.Valid {
				lpn = int(lp.Int64)
			}
			if rp.Valid {
				rpn = int(rp.Int64)
			}
			c := policy.Contact{Host: f.HostID, Direction: f.Direction, Protocol: f.Protocol, RemoteIP: rip, LocalPort: lpn, RemotePort: rpn, Process: f.Path, Cgroup: cg, UID: uid}
			if b, e := policy.ParseIdentity(f.Path, f.HostID, f.Proc); e == nil {
				c.Process, c.Cgroup, c.UID = b.Path, b.Cgroup, b.UID
			}
			name, st, detail := d.explain(c, now)
			f.Rule = name
			if detail != "" {
				if f.Tip != "" {
					f.Tip += "; "
				}
				f.Tip += detail
			}
			if st == "block" && f.State == "open" {
				f.State = "block"
			}
		}
		out = append(out, f)
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	s := "?"
	for i := 1; i < n; i++ {
		s += ",?"
	}
	return s
}

func readUIAudit(db *checkedRead, q stateQuery) []uiAudit {
	query := `SELECT datetime(at_ms/1000,'unixepoch','localtime'), actor, action, COALESCE(object,''), COALESCE(detail,''), COALESCE(src_ip,'') FROM audit_log WHERE 1=1`
	var args []any
	if q.FromMS > 0 {
		query += ` AND at_ms>=?`
		args = append(args, q.FromMS)
	}
	if q.ToMS > 0 {
		query += ` AND at_ms<=?`
		args = append(args, q.ToMS)
	}
	if q.Action != "" {
		if cond, ok := auditKinds[q.Action]; ok {
			query += ` AND (` + cond + `)`
		} else {
			query += ` AND action LIKE ?`
			args = append(args, "%"+q.Action+"%")
		}
	}
	switch q.Who {
	case "me":
		query += ` AND ` + auditByAdmin
	case "auto":
		query += ` AND NOT ` + auditByAdmin
	}
	if q.Addr != "" {
		query += ` AND (object LIKE ? OR detail LIKE ?)`
		args = append(args, "%"+q.Addr+"%", "%"+q.Addr+"%")
	}
	query += ` ORDER BY at_ms DESC LIMIT 200`
	ar, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	type auditRow struct {
		a           uiAudit
		detail, src string
	}
	// polishAudit ходит за именами в базу — курсор к этому времени закрыт (см. readUIFlows).
	var raw []auditRow
	for ar.Next() {
		var r auditRow
		if ar.Scan(&r.a.When, &r.a.Actor, &r.a.Action, &r.a.Object, &r.detail, &r.src) != nil {
			continue
		}
		raw = append(raw, r)
	}
	ar.Close()
	out := make([]uiAudit, 0, len(raw))
	for _, r := range raw {
		a := r.a
		a.Actor, a.Action, a.Object = polishAudit(db, a.Actor, a.Action, a.Object, r.detail, r.src)
		out = append(out, a)
	}
	return out
}

// Лента тревог: все, новые сверху. Живые не вытесняются закрытыми.
const alertFeedMax = 50

func listUIAlerts(db *checkedRead) []uiAlert {
	rows, err := db.Query(`SELECT alert_id, rule_id, host_id, opened_at_ms, closed_at_ms, summary, backfill, seen_at_ms, COALESCE(closed_by,''), COALESCE(close_note,''), dedup_key
		FROM alerts WHERE closed_at_ms IS NULL
		UNION ALL SELECT * FROM (SELECT alert_id, rule_id, host_id, opened_at_ms, closed_at_ms, summary, backfill, seen_at_ms, COALESCE(closed_by,''), COALESCE(close_note,''), dedup_key
		FROM alerts WHERE closed_at_ms IS NOT NULL ORDER BY opened_at_ms DESC LIMIT ?)
		ORDER BY 4 DESC`, alertFeedMax)
	if err != nil {
		return []uiAlert{}
	}
	var raw []uiAlert
	var dedups []string
	for rows.Next() {
		var a uiAlert
		var closed, seen sql.NullInt64
		var backfill int
		var opened int64
		var by, note, dedup string
		if rows.Scan(&a.ID, &a.Rule, &a.HostID, &opened, &closed, &a.Text, &backfill, &seen, &by, &note, &dedup) != nil {
			continue
		}
		dedups = append(dedups, dedup)
		a.VM = a.HostID
		if a.HostID == "monitor" || a.HostID == "" {
			a.VM = "monitor"
		}
		a.At = fmtMS(opened)
		a.OpenedMS = opened
		a.Kind = a.Rule
		a.Hist = backfill != 0
		a.State = alertState(closed, seen, by)
		a.Seen = seen.Valid
		if closed.Valid {
			a.Closed = fmtMS(closed.Int64)
			a.ClosedBy = by
			a.CloseText = alertCloseText(by, note)
		}
		raw = append(raw, a)
	}
	rows.Close()
	now := store.NowMS()
	out := make([]uiAlert, 0, len(raw))
	for i, a := range raw {
		dedup := ""
		if i < len(dedups) {
			dedup = dedups[i]
		}
		if a.Rule == "storm" {
			var backend string
			_ = db.db.QueryRow(`SELECT COALESCE(fw_backend,'') FROM agents WHERE host_id=? AND trust_state='trusted' LIMIT 1`, a.HostID).Scan(&backend)
			a.IPTables = backend == "iptables"
		}
		var addr string
		if err := db.db.QueryRow(`SELECT ref_id FROM alert_refs WHERE alert_id=? AND ref_kind='ip' LIMIT 1`, a.ID).Scan(&addr); err != nil && err != sql.ErrNoRows {
			db.record(err)
		}
		a.Addr = addr
		if a.Addr == "" {
			a.Addr = lastIPv4(a.Text)
		}
		// Карточка «вернулся после 7 суток» одна на адрес и копит баны; id v7 — берём последний.
		var blockRef string
		if err := db.db.QueryRow(`SELECT ref_id FROM alert_refs WHERE alert_id=? AND ref_kind='block' ORDER BY ref_id DESC LIMIT 1`, a.ID).Scan(&blockRef); err != nil && err != sql.ErrNoRows {
			db.record(err)
		}
		attachAlertBan(db, &a, alertBanID(a.Rule, dedup, blockRef), now)
		title := hostTitle(db.db, a.HostID)
		a.Text = alertEventText(a, title)
		a.Hint = alertHint(a.Rule, a.Hist)
		out = append(out, a)
	}
	if out == nil {
		out = []uiAlert{}
	}
	return out
}

// alertBanID is the ban this alert is about. New alerts store it in alert_refs.
// Older scan and ssh alerts keep it in the dedup key: «scan/<id>».
func alertBanID(rule, dedup, ref string) string {
	if ref != "" {
		return ref
	}
	if rule != "scan" && rule != "ssh" {
		return ""
	}
	prefix := rule + "/"
	if !strings.HasPrefix(dedup, prefix) {
		return ""
	}
	id := dedup[len(prefix):]
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}

func banShownState(b banRecord, now int64) string {
	if b.State == "active" && b.ExpiresAt > 0 && b.ExpiresAt <= now {
		return "expired"
	}
	return b.State
}

func attachAlertBan(db *checkedRead, a *uiAlert, id string, now int64) {
	if a == nil || id == "" {
		return
	}
	a.BanID = id
	b, err := readBan(db.db, id)
	if err == sql.ErrNoRows {
		a.BanState = "missing"
		return
	}
	if err != nil {
		db.record(err)
		return
	}
	a.BanState = banShownState(b, now)
	a.BanAt = fmtMS(b.CreatedAt)
	a.BanUntilMS = b.ExpiresAt
	if b.ExpiresAt > 0 {
		a.BanUntil = fmtMS(b.ExpiresAt)
	} else {
		a.BanUntil = "навсегда"
	}
	a.BanScope = scopeLabel(namedHosts(db.db, b.Hosts), namedHosts(db.db, b.Except))
	switch a.BanState {
	case "removed":
		a.BanGone = fmtMS(b.RemovedAt)
	case "expired":
		a.BanGone = fmtMS(b.ExpiresAt)
	}
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
		Op string `json:"op"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in.ID == "" {
		http.Error(w, "json", 400)
		return
	}
	// seen — карточку закрыли, значит видел; keep — шторм: не снимать
	// (видел, защита снимется сама); open — снять шторм сразу;
	// close — закрыть вручную; restore — вернуть бан, снятый с консоли.
	switch in.Op {
	case "seen", "keep", "open", "close", "history", "restore":
	default:
		http.Error(w, "неверное действие", 400)
		return
	}
	err := s.st.Update(func(tx *sql.Tx) error {
		now := store.NowMS()
		switch in.Op {
		case "seen":
			rule, _, err := alertOpen(tx, in.ID)
			if err == errAlertClosed {
				return markAlertSeen(tx, in.ID, now)
			}
			if err != nil {
				return err
			}
			// Автобан уже поставлен. Закрытая карточка — «видел»: строка зелёная, сирена молчит.
			if rule == "scan" || rule == "ssh" {
				_, err = closeAlert(tx, in.ID, "adm", "видел", now)
				return err
			}
			return markAlertSeen(tx, in.ID, now)
		case "restore":
			return restorePausedFromAlert(tx, in.ID, now)
		case "keep":
			rule, _, err := alertOpen(tx, in.ID)
			if err != nil {
				return err
			}
			if rule != "storm" {
				return fmt.Errorf("не снимать — только для шторма")
			}
			if err = markAlertSeen(tx, in.ID, now); err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)`,
				idgen.NewV7(), now, "adm", "шторм: оставил", in.ID)
			return err
		case "open":
			rule, host, err := alertOpen(tx, in.ID)
			if err != nil {
				return err
			}
			if rule != "storm" {
				return fmt.Errorf("снять шторм — только для шторма")
			}
			if err = endStormNow(tx, host, now); err != nil {
				return err
			}
			_, err = closeAlert(tx, in.ID, "adm", "снял шторм", now)
			return err
		default:
			if _, _, err := alertOpen(tx, in.ID); err != nil {
				return err
			}
			_, err := closeAlert(tx, in.ID, "adm", "закрыл вручную", now)
			return err
		}
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server) handleQuestion(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
		Op string `json:"op"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || in.ID == "" {
		http.Error(w, "json", 400)
		return
	}
	if in.Op != "dismiss" {
		http.Error(w, "неверное действие", 400)
		return
	}
	err := s.st.Update(func(tx *sql.Tx) error {
		if err := s.flushQuestionRepeats(tx, store.NowMS()); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE learn_questions SET status='answered',answer='dismiss' WHERE question_id=? AND status='open'`, in.ID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return fmt.Errorf("вопрос уже закрыт")
		}
		_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), "adm", "снял вопрос", in.ID)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

func flowEndpoint(ip string, port sql.NullInt64) string {
	if port.Valid {
		return net.JoinHostPort(ip, strconv.FormatInt(port.Int64, 10))
	}
	return ip
}
