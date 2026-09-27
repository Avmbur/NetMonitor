package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"netmonitor/deploy"
	"netmonitor/internal/idgen"
	"netmonitor/internal/policy"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

const monitorAgentName = "монитор"

const (
	monitorRulePort  = "monitor-svc-port"
	monitorRuleICMP  = "monitor-svc-icmp"
	monitorRuleSSH   = "monitor-svc-ssh"
	monitorRuleWhois = "monitor-svc-whois"
	defaultLAN       = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
)

var selfInstallHook func(s *Server, endpoint, pin, token string) error
var selfInstallWait = 45 * time.Second

type monitorAgent struct {
	AgentID, HostID, Trust, Name, Src string
}

func (s *Server) listenAddr() string {
	h, _ := store.SettingDB(s.st.DB, "listen_host")
	return strings.TrimSpace(h)
}

func isLoopbackIP(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.IsLoopback()
}

func (s *Server) findMonitorAgent() (monitorAgent, bool, error) {
	listen := s.listenAddr()
	var marked string
	_ = s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='monitor_host_id'`).Scan(&marked)
	rows, err := s.st.DB.Query(`SELECT a.agent_id, a.host_id, a.trust_state, COALESCE(a.display_name,''), COALESCE(a.last_src_ip,'')
		FROM agents a WHERE a.trust_state IN ('pending','trusted','quarantined')`)
	if err != nil {
		return monitorAgent{}, false, err
	}
	defer rows.Close()
	var hit monitorAgent
	found := false
	for rows.Next() {
		var a monitorAgent
		if err := rows.Scan(&a.AgentID, &a.HostID, &a.Trust, &a.Name, &a.Src); err != nil {
			return monitorAgent{}, false, err
		}
		match := marked != "" && a.HostID == marked
		if a.Name == monitorAgentName {
			match = true
		}
		if listen != "" && (a.Src == listen || isLoopbackIP(listen) && isLoopbackIP(a.Src)) {
			match = true
		}
		if listen != "" && inventoryHasAddr(s.st.DB, a.HostID, listen) {
			match = true
		}
		if !match {
			continue
		}
		if a.Trust == "trusted" || !found {
			hit, found = a, true
		}
	}
	return hit, found, rows.Err()
}

func (s *Server) handleInstallSelf(w http.ResponseWriter, r *http.Request) {
	if _, ok, err := s.findMonitorAgent(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	} else if ok {
		http.Error(w, "агент монитора уже установлен", 409)
		return
	}
	tok, err := NewToken(s.cfg.DataDir)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	endpoint, pin, err := s.selfEndpointPin(r.Host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := s.startSelfInstall(endpoint, pin, tok); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	ag, err := s.waitTokenAgent(tok, selfInstallWait)
	if err != nil {
		http.Error(w, err.Error(), 504)
		return
	}
	resume := false
	if hid, _ := peekOrphanHost(s.st.DB, ag.Name, ag.Src, ag.HostID); hid != "" {
		resume = true
	}
	if err := s.applyAgentChange(ag.AgentID, "trust", monitorAgentName, r.RemoteAddr, resume); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	hostID := ag.HostID
	_ = s.st.DB.QueryRow(`SELECT host_id FROM agents WHERE agent_id=?`, ag.AgentID).Scan(&hostID)
	if err := s.markMonitorHost(hostID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"ok": "1", "host_id": hostID, "agent_id": ag.AgentID})
}

func parseInstallCmd(cmd string) (endpoint, pin, token string, err error) {
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if i+1 >= len(fields) {
			continue
		}
		next := strings.Trim(fields[i+1], "'\"")
		switch f {
		case "--monitor":
			endpoint = next
		case "--pin":
			pin = next
		case "--token":
			token = next
		}
	}
	if endpoint == "" || pin == "" || token == "" {
		return "", "", "", fmt.Errorf("не собралась команда установки")
	}
	return endpoint, pin, token, nil
}

func (s *Server) selfEndpointPin(requestHost string) (endpoint, pin string, err error) {
	cmd, err := s.installationCommand("unused", requestHost)
	if err != nil {
		return "", "", err
	}
	endpoint, pin, _, err = parseInstallCmd(strings.Replace(cmd, "--token unused", "--token unused", 1))
	if err != nil {
		return "", "", err
	}
	if s.bundle != nil && s.bundle.ServerTLS != nil && len(s.bundle.ServerTLS.Certificate) > 0 {
		p, e := tlsutil.PublicKeyPin(s.bundle.ServerTLS.Certificate[0])
		if e == nil {
			pin = p
		}
	}
	return endpoint, pin, nil
}

func (s *Server) startSelfInstall(endpoint, pin, token string) error {
	if selfInstallHook != nil {
		return selfInstallHook(s, endpoint, pin, token)
	}
	req := filepath.Join(s.dataDir(), "self-agent.request")
	body := "MONITOR=" + endpoint + "\nPIN=" + pin + "\nTOKEN=" + token + "\n"
	if err := os.WriteFile(req, []byte(body), 0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return runEmbeddedInstaller(endpoint, pin, token)
	}
	_ = exec.Command("systemctl", "start", "nmagent-self.service").Run()
	return nil
}

func runEmbeddedInstaller(endpoint, pin, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-s", "--", "--monitor", endpoint, "--pin", pin, "--token", token)
	cmd.Stdin = strings.NewReader(deploy.AgentInstaller)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("установка агента: %v\n%s", err, out)
	}
	return nil
}

func (s *Server) waitTokenAgent(token string, d time.Duration) (monitorAgent, error) {
	hash := idgen.TokenHash(token)
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		var ag monitorAgent
		err := s.st.DB.QueryRow(`SELECT a.agent_id, a.host_id, a.trust_state, COALESCE(a.display_name,''), COALESCE(a.last_src_ip,'')
			FROM enroll_tokens t JOIN agents a ON a.agent_id=t.used_by_agent
			WHERE t.token_hash=?`, hash).Scan(&ag.AgentID, &ag.HostID, &ag.Trust, &ag.Name, &ag.Src)
		if err == nil {
			return ag, nil
		}
		if err != sql.ErrNoRows {
			return monitorAgent{}, err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return monitorAgent{}, fmt.Errorf("агент на мониторе не подключился")
}

func (s *Server) markMonitorHost(hostID string) error {
	now := store.NowMS()
	raw, _ := json.Marshal(hostControl{Mode: "learn"})
	return s.st.Update(func(tx *sql.Tx) error {
		if err := store.PutSetting(tx, "monitor_host_id", hostID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, "host_control:"+hostID, string(raw)); err != nil {
			return err
		}
		if err := s.syncMonitorServiceRules(tx, hostID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=?`, hostID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail) VALUES(?,?,?,?,?,?)`,
			idgen.NewV7(), now, "adm", "управление сервером: mode", hostID, string(raw))
		return err
	})
}

func (s *Server) ensureMonitorServiceRules() error {
	mon, ok, err := s.findMonitorAgent()
	if err != nil || !ok || mon.HostID == "" {
		return err
	}
	return s.st.Update(func(tx *sql.Tx) error {
		return s.syncMonitorServiceRules(tx, mon.HostID)
	})
}

func (s *Server) syncMonitorServiceRules(tx *sql.Tx, hostID string) error {
	if hostID == "" {
		return nil
	}
	nets := splitCIDRs(settingValue(tx, "lan", defaultLAN))
	if len(nets) == 0 {
		nets = splitCIDRs(defaultLAN)
	}
	port := settingInt(tx, "listen_port", 8443)
	if port < 1 || port > 65535 {
		port = 8443
	}
	sshPort := hostSSHPort(tx, hostID)
	rules := []policy.Rule{
		{
			ID: monitorRulePort, Name: "служебные · порт монитора (руками не трогать)", Order: 990,
			Match: policy.Match{Direction: "any", Protocol: "tcp", AnyPort: port, Networks: nets},
		},
		{
			ID: monitorRuleICMP, Name: "служебные · ICMP (руками не трогать)", Order: 991,
			Match: policy.Match{Direction: "any", Protocol: "icmp", Networks: nets},
		},
		{
			ID: monitorRuleSSH, Name: "служебные · SSH (руками не трогать)", Order: 992,
			Match: policy.Match{Direction: "any", Protocol: "tcp", AnyPort: sshPort, Networks: nets},
		},
		{
			ID: monitorRuleWhois, Name: "служебные · whois (руками не трогать)", Order: 993,
			Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 43},
		},
	}
	now := store.NowMS()
	changed := false
	for i := range rules {
		r := rules[i]
		r.Enabled = true
		r.Action = "allow"
		r.Hosts = []string{hostID}
		did, err := upsertMonitorRule(tx, r, now)
		if err != nil {
			return err
		}
		changed = changed || did
	}
	if !changed {
		return nil
	}
	_, err := tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=? AND trust_state='trusted'`, hostID)
	return err
}

// hostSSHPorts are the ports sshd listens on, as the host's agent reported them.
// An agent without ssh_ports reports one port; nothing reported means factory 22.
func hostSSHPorts(db policyReader, hostID string) []int {
	var inv string
	if db.QueryRow(`SELECT v FROM settings WHERE k=?`, "inventory:"+hostID).Scan(&inv) != nil || inv == "" {
		return []int{22}
	}
	var h struct {
		SSHPort  *int  `json:"ssh_port"`
		SSHPorts []int `json:"ssh_ports"`
	}
	if json.Unmarshal([]byte(inv), &h) != nil {
		return []int{22}
	}
	var out []int
	for _, p := range h.SSHPorts {
		if p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	if len(out) == 0 && h.SSHPort != nil && *h.SSHPort >= 1 && *h.SSHPort <= 65535 {
		out = []int{*h.SSHPort}
	}
	if len(out) == 0 {
		return []int{22}
	}
	return out
}

// hostSSHPort is the one sshd port for the monitor's service rule: not 22 if sshd has one.
func hostSSHPort(db policyReader, hostID string) int {
	ports := hostSSHPorts(db, hostID)
	for _, p := range ports {
		if p != 22 {
			return p
		}
	}
	return ports[0]
}

func upsertMonitorRule(tx *sql.Tx, r policy.Rule, now int64) (bool, error) {
	var ver int64
	var oldRaw string
	err := tx.QueryRow(`SELECT version, payload FROM policy_rules WHERE rule_id=?`, r.ID).Scan(&ver, &oldRaw)
	if err == sql.ErrNoRows {
		r.Version = 1
	} else if err != nil {
		return false, err
	} else {
		var old policy.Rule
		if json.Unmarshal([]byte(oldRaw), &old) == nil {
			r.Version = old.Version
			if monitorRuleSame(old, r) {
				return false, nil
			}
		}
		r.Version = ver + 1
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES(?,?,?,?)
		ON CONFLICT(rule_id) DO UPDATE SET version=excluded.version,sort_order=excluded.sort_order,payload=excluded.payload`,
		r.ID, r.Version, r.Order, string(raw)); err != nil {
		return false, err
	}
	return true, answerPolicyQuestions(tx, r, "", nil, now)
}

func monitorRuleSame(a, b policy.Rule) bool {
	if a.Name != b.Name || a.Action != b.Action || a.Enabled != b.Enabled || a.Order != b.Order {
		return false
	}
	if a.Match.Direction != b.Match.Direction || a.Match.Protocol != b.Match.Protocol || a.Match.AnyPort != b.Match.AnyPort || a.Match.LocalPort != b.Match.LocalPort || a.Match.RemotePort != b.Match.RemotePort {
		return false
	}
	if len(a.Hosts) != len(b.Hosts) || len(a.Match.Networks) != len(b.Match.Networks) {
		return false
	}
	for i := range a.Hosts {
		if a.Hosts[i] != b.Hosts[i] {
			return false
		}
	}
	for i := range a.Match.Networks {
		if a.Match.Networks[i] != b.Match.Networks[i] {
			return false
		}
	}
	return true
}

func inventoryHasAddr(db *sql.DB, hostID, addr string) bool {
	var inv string
	if db.QueryRow(`SELECT v FROM settings WHERE k=?`, "inventory:"+hostID).Scan(&inv) != nil || inv == "" {
		return false
	}
	var h struct {
		Addresses []string `json:"addresses"`
	}
	if json.Unmarshal([]byte(inv), &h) != nil {
		return false
	}
	for _, a := range h.Addresses {
		if a == addr {
			return true
		}
	}
	return false
}
