package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"netmonitor/internal/idgen"
	"netmonitor/internal/policy"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ruleInput struct {
	Networks                                                                            []string `json:"networks"`
	ID, Name, Kind, IP, Addr, Proto, Direction, Dir, PortSide, Group, Process, When, Op string
	HostID                                                                              string `json:"host_id"`
	QuestionID                                                                          string `json:"question_id"`
	Version                                                                             int64
	Enabled                                                                             *bool
	Order                                                                               int
	Port                                                                                any
	Except                                                                              []string
	Hosts                                                                               json.RawMessage
	Together                                                                            *bool
	FromMS                                                                              int64            `json:"from_ms"`
	UntilMS                                                                             int64            `json:"until_ms"`
	Bindings                                                                            []policy.Binding `json:"bindings"`
	ProcessBindings                                                                     []string         `json:"processBindings"`
	Validity                                                                            struct {
		Mode, Preset, DurUnit, From, To string
		DurN                            int
	} `json:"validity"`
}

func parseScope(raw json.RawMessage, host string) ([]string, error) {
	if len(raw) == 0 {
		if host != "" {
			return []string{host}, nil
		}
		return nil, nil
	}
	if string(raw) == `"all"` || string(raw) == "null" {
		return nil, nil
	}
	var hs []string
	if err := json.Unmarshal(raw, &hs); err != nil || len(hs) == 0 {
		return nil, fmt.Errorf("выбери серверы")
	}
	seen := map[string]bool{}
	for _, h := range hs {
		if h == "" || seen[h] {
			return nil, fmt.Errorf("неверный набор серверов")
		}
		seen[h] = true
	}
	return hs, nil
}
func ruleFromInput(in ruleInput, now int64) (policy.Rule, error) {
	r := policy.Rule{ID: in.ID, Name: strings.TrimSpace(in.Name), Version: in.Version, Order: in.Order, Enabled: true, Action: in.Kind, GroupID: in.Group, FromMS: in.FromMS, UntilMS: in.UntilMS, Once: in.When == "once", Except: in.Except}
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	}
	if r.Action == "" {
		r.Action = "allow"
	}
	if r.Action != "allow" && r.Action != "deny" {
		return r, fmt.Errorf("неверное действие правила")
	}
	var err error
	r.Hosts, err = parseScope(in.Hosts, in.HostID)
	if err != nil {
		return r, err
	}
	dir := in.Direction
	if dir == "" {
		dir = in.Dir
	}
	r.Match = policy.Match{Protocol: in.Proto, Direction: dir, Process: strings.TrimSpace(in.Process)}
	addr := in.Addr
	if addr == "" {
		addr = in.IP
	}
	if addr != "" {
		p, e := parseMember(addr)
		if e != nil {
			if isNameMask(addr) {
				r.Match.Names = []string{strings.ToLower(strings.TrimSuffix(addr, "."))}
			} else {
				return r, e
			}
		} else {
			r.Match.Networks = []string{p.String()}
		}
	}
	if in.Networks != nil {
		if len(in.Networks) == 0 {
			return r, fmt.Errorf("пустой список адресов")
		}
		if addr != "" && (len(r.Match.Networks) != 1 || r.Match.Networks[0] != in.Networks[0]) {
			return r, fmt.Errorf("адрес и список сетей расходятся")
		}
		r.Match.Networks = in.Networks
	}
	port := 0
	if in.Port != nil && fmt.Sprint(in.Port) != "" {
		var e error
		port, e = strconv.Atoi(fmt.Sprint(in.Port))
		if e != nil {
			return r, fmt.Errorf("неверный порт")
		}
	}

	switch in.PortSide {
	case "local":
		r.Match.LocalPort = port
	case "any":
		r.Match.AnyPort = port
	case "", "remote":
		r.Match.RemotePort = port
	default:
		return r, fmt.Errorf("неверная сторона порта")
	}
	if err := attachProcessBindings(&r, in); err != nil {
		return r, err
	}
	switch in.Validity.Mode {
	case "", "preset", "range", "dur":
	default:
		return r, fmt.Errorf("неверный срок")
	}
	if in.Validity.Mode == "dur" && in.Validity.DurN <= 0 {
		return r, fmt.Errorf("длительность должна быть положительной")
	}
	if in.Validity.Mode == "preset" && in.Validity.Preset != "" && in.Validity.Preset != "forever" && in.Validity.Preset != "once" {
		return r, fmt.Errorf("неверный срок")
	}
	if in.Validity.Preset == "once" {
		r.Once = true
	}
	if in.Validity.Mode == "dur" && in.Validity.DurN > 0 && r.UntilMS == 0 {
		unit := map[string]int64{"m": 60000, "h": 3600000, "d": 86400000}[in.Validity.DurUnit]
		if unit == 0 {
			return r, fmt.Errorf("единица срока")
		}
		r.UntilMS = now + int64(in.Validity.DurN)*unit
	}
	if in.Validity.Mode == "range" {
		from, until, err := policy.CalendarBounds(in.Validity.From, in.Validity.To, time.Local)
		if err != nil {
			return r, err
		}
		r.FromMS, r.UntilMS = from, until
	}
	if r.Name == "" {
		r.Name = addr
		if r.Name == "" {
			r.Name = "правило"
		}
	}
	return r, policy.Executable(r)
}

func processOptional(r policy.Rule) bool {
	return len(r.Match.Networks) > 0 || len(r.Match.Names) > 0 || r.Match.LocalPort > 0 || r.Match.RemotePort > 0 || r.Match.AnyPort > 0 || r.GroupID != ""
}

func attachProcessBindings(r *policy.Rule, in ruleInput) error {
	host := in.HostID
	if host == "" && len(r.Hosts) == 1 {
		host = r.Hosts[0]
	}
	var out []policy.Binding
	if len(in.Bindings) > 0 {
		for _, b := range in.Bindings {
			if b.Host == "" {
				b.Host = host
			}
			if b.Name == "" {
				b.Name = r.Match.Process
			}
			if b.Cgroup != "" {
				b.Cgroup = policy.NormalizeCgroup(b.Cgroup)
			}
			if err := b.Enforceable(); err != nil {
				if processOptional(*r) {
					continue
				}
				return err
			}
			out = append(out, b)
		}
	} else {
		seen := map[string]bool{}
		add := func(raw, h string) error {
			raw = strings.TrimSpace(raw)
			if raw == "" || seen[h+"|"+raw] {
				return nil
			}
			b, err := policy.ParseIdentity(raw, h, r.Match.Process)
			if err != nil {
				if processOptional(*r) {
					return nil
				}
				return err
			}
			if err = b.Enforceable(); err != nil {
				if processOptional(*r) {
					return nil
				}
				return err
			}
			seen[h+"|"+raw] = true
			out = append(out, b)
			return nil
		}
		for _, raw := range in.ProcessBindings {
			if err := add(raw, host); err != nil {
				return err
			}
		}
		if len(out) == 0 && r.Match.Process != "" {
			if err := add(r.Match.Process, host); err != nil {
				return err
			}
		}
	}
	if len(out) == 0 {
		if processOptional(*r) {
			r.Match.Process = ""
			r.Match.Cgroup = ""
			r.Match.UID = nil
		}
		return nil
	}
	if r.Match.Process == "" {
		r.Match.Process = out[0].Name
	}
	r.Match.Bindings = out
	return nil
}
func readPolicyRules(db policyReader) ([]policy.Rule, error) {
	rows, err := db.Query("SELECT payload FROM policy_rules ORDER BY sort_order,rule_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.Rule{}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r policy.Rule
		if err = json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func hostRules(db policyReader, host string) ([]policy.Rule, error) {
	rs, err := readPolicyRules(db)
	if err != nil {
		return nil, err
	}
	out := []policy.Rule{}
	for _, r := range rs {
		if !r.OnHost(host) {
			continue
		}
		r.Match.Bindings = policy.BindingsForHost(r.Match.Bindings, host)
		r.OnceUsed = r.SpentOn(host)
		r.OnceUsedHosts = nil
		if r.GroupID != "" {
			nets, err := groupNetworks(db, r.GroupID)
			if err != nil {
				return nil, err
			}
			r.Match.Networks = policy.IntersectNetworks(r.Match.Networks, nets)
		}
		r, err = expandRuleNames(db, r)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	// Starter SSH also opens every other port sshd listens on: with 22 only,
	// learning mode would swallow the admin's login on 2222.
	return policy.ExpandStarterSSH(out, hostSSHPorts(db, host)), nil
}
func groupNetworks(db policyReader, id string) ([]string, error) {
	out, err := policyStrings(db, "SELECT cidr FROM ip_group_members WHERE group_id=?", id)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	ps, err := policyStrings(db, "SELECT pattern FROM ip_group_patterns WHERE group_id=?", id)
	if err != nil {
		return nil, err
	}
	found, err := resolvePatterns(db, ps)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		for _, ip := range found[strings.ToLower(strings.TrimSpace(p))] {
			px, e := parseMember(ip)
			if e != nil {
				return nil, e
			}
			out = append(out, px.String())
		}
	}
	return out, nil
}
func hostGroups(db policyReader, host string) ([]policy.Rule, error) {
	check, err := db.Query("SELECT pattern FROM ip_group_patterns LIMIT 0")
	if err != nil {
		return nil, err
	}
	check.Close()
	rows, err := db.Query("SELECT group_id,name,policy,sort_order,hosts_json FROM ip_groups WHERE group_id NOT IN(SELECT group_id FROM ip_group_host_excl WHERE host_id=?) ORDER BY sort_order,group_id", host)
	if err != nil {
		return nil, err
	}
	var out []policy.Rule
	for rows.Next() {
		r := policy.Rule{Enabled: true}
		var raw string
		if err = rows.Scan(&r.ID, &r.Name, &r.Action, &r.Order, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if r.Action == "block" {
			r.Action = "deny"
		}
		r.Hosts, err = parseScope(json.RawMessage(raw), "")
		if err != nil {
			rows.Close()
			return nil, err
		}
		if r.OnHost(host) {
			out = append(out, r)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Match.Networks, err = groupNetworks(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		names, err := policyStrings(db, "SELECT pattern FROM ip_group_patterns WHERE group_id=?", out[i].ID)
		if err != nil {
			return nil, err
		}
		if len(names) > 0 {
			// The agent resolves these names itself, so a new address is covered
			// before the next round trip would otherwise raise a learn question.
			out[i].Match.Names = names
		}
	}
	return policy.Ordered(out), nil
}
func (s *Server) handlePolicyRule(w http.ResponseWriter, r *http.Request) {
	var in ruleInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	// Preserve the historical snake_case request fields used by question callers.
	var qid string
	qid = in.QuestionID
	now := time.Now().Unix() * 1000
	rule, err := ruleFromInput(in, now)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var seed []seededAddr
	if in.Op != "delete" {
		seed = resolveRuleNames(rule.Match.Names)
	}
	err = s.st.Update(func(tx *sql.Tx) error {
		if in.Op == "delete" {
			if isServiceRuleID(in.ID) {
				return fmt.Errorf("служебное правило, руками не трогать")
			}
			res, err := tx.Exec("DELETE FROM policy_rules WHERE rule_id=? AND version=?", in.ID, in.Version)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return fmt.Errorf("правило уже изменено")
			}
		} else {
			for _, h := range rule.Hosts {
				var n int
				if err := tx.QueryRow("SELECT count(*) FROM hosts WHERE host_id=?", h).Scan(&n); err != nil {
					return err
				}
				if n != 1 {
					return fmt.Errorf("неизвестный сервер")
				}
			}
			if rule.GroupID != "" {
				var n int
				if err := tx.QueryRow("SELECT count(*) FROM ip_groups WHERE group_id=?", rule.GroupID).Scan(&n); err != nil {
					return err
				}
				if n != 1 {
					return fmt.Errorf("неизвестная группа")
				}
			}
			if isServiceRuleID(in.ID) {
				return fmt.Errorf("служебное правило, руками не трогать")
			}
			if dup, err := findDuplicateRule(tx, rule); err != nil {
				return err
			} else if dup != "" {
				return fmt.Errorf("уже есть такое правило: %s", dup)
			}
			if rule.ID == "" {
				rule.ID = idgen.NewV7()
				rule.Version = 1
			} else {
				var raw string
				var v int64
				if err := tx.QueryRow("SELECT version,payload FROM policy_rules WHERE rule_id=?", rule.ID).Scan(&v, &raw); err != nil {
					return err
				}
				if v != rule.Version {
					return fmt.Errorf("правило уже изменено; обнови форму")
				}
				var prev policy.Rule
				if err := json.Unmarshal([]byte(raw), &prev); err != nil {
					return err
				}
				rule.OnceUsed = prev.OnceUsed
				rule.OnceUsedHosts = prev.OnceUsedHosts
				if !rule.Once {
					rule.OnceUsed = false
					rule.OnceUsedHosts = nil
				}
				rule.Version++
			}
			raw, err := json.Marshal(rule)
			if err != nil {
				return err
			}
			_, err = tx.Exec("INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES(?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET version=excluded.version,sort_order=excluded.sort_order,payload=excluded.payload", rule.ID, rule.Version, rule.Order, string(raw))
			if err != nil {
				return err
			}
			if err = rememberResolved(tx, rule.Hosts, seed, now); err != nil {
				return err
			}
			if err = s.rememberLiveNames(tx, rule.Match.Names); err != nil {
				return err
			}
			if err := s.flushQuestionRepeats(tx, now); err != nil {
				return err
			}
			if err = answerPolicyQuestions(tx, rule, qid, in.Together, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "adm", "правило: "+in.Op, rule.ID); err != nil {
			return err
		}
		return bumpTrusted(tx)
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, rule)
}
func answerPolicyQuestions(tx *sql.Tx, rule policy.Rule, qid string, together *bool, now int64) error {
	if !rule.Active(now) {
		return nil
	}
	rows, err := tx.Query("SELECT question_id,host_id,direction,protocol,remote_ip,COALESCE(local_port,0),COALESCE(remote_port,0),COALESCE(proc_path,''),COALESCE(proc_comm,'') FROM learn_questions WHERE status='open'")
	if err != nil {
		return err
	}
	type row struct {
		id, host string
		c        policy.Contact
	}
	var qs []row
	for rows.Next() {
		var q row
		var comm string
		if err = rows.Scan(&q.id, &q.host, &q.c.Direction, &q.c.Protocol, &q.c.RemoteIP, &q.c.LocalPort, &q.c.RemotePort, &q.c.Process, &comm); err != nil {
			rows.Close()
			return err
		}
		q.c.Host = q.host
		if b, e := policy.ParseIdentity(q.c.Process, q.host, comm); e == nil {
			q.c.Process, q.c.Cgroup, q.c.UID = b.Path, b.Cgroup, b.UID
		}
		qs = append(qs, q)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if rule.GroupID != "" {
		var nets []string
		nets, err = groupNetworks(tx, rule.GroupID)
		rule.Match.Networks = policy.IntersectNetworks(rule.Match.Networks, nets)
		if err != nil {
			return err
		}
	}
	rule, err = expandRuleNames(tx, rule)
	if err != nil {
		return err
	}
	for _, q := range qs {
		if together != nil && !*together && q.id != qid {
			continue
		}
		if !rule.OnHost(q.host) || !rule.Match.Matches(q.c) {
			continue
		}
		gs, err := hostGroups(tx, q.host)
		if err != nil {
			return err
		}
		if d, ok := policy.Evaluate(gs, q.host, q.c, now); ok && (d.Action == "deny" || d.Action == "alert") {
			continue
		}
		if _, err = tx.Exec("UPDATE learn_questions SET status='answered',answer=? WHERE question_id=?", rule.Action, q.id); err != nil {
			return err
		}
	}
	return nil
}
func ordinaryAllow(tx *sql.Tx, host string, c policy.Contact, now int64) (bool, error) {
	r, err := allowingRule(tx, host, c, now)
	return r != nil, err
}

func allowingRule(tx *sql.Tx, host string, c policy.Contact, now int64) (*policy.Rule, error) {
	rs, err := hostRules(tx, host)
	if err != nil {
		return nil, err
	}
	d, ok := policy.Evaluate(rs, host, c, now)
	if !ok || d.Action != "allow" {
		return nil, nil
	}
	for i := range rs {
		if rs[i].ID == d.ID {
			return &rs[i], nil
		}
	}
	return nil, nil
}

// An allow shields a source from an automatic ban only when the rule names
// that address: the starter set opens SSH for everybody, and a blanket rule
// is not a decision about this particular source. Otherwise a brute force on
// a server with the starter SSH rule could never be banned.
func allowForAddress(tx *sql.Tx, host string, c policy.Contact, now int64) (bool, error) {
	r, err := allowingRule(tx, host, c, now)
	if r == nil || err != nil {
		return false, err
	}
	if len(r.Match.Networks) == 0 {
		return false, nil
	}
	for _, n := range r.Match.Networks {
		if p, e := netip.ParsePrefix(n); e == nil && p.Bits() == 0 {
			return false, nil
		}
	}
	return true, nil
}
func (s *Server) listPolicyRules(db *checkedRead) []policy.Rule {
	rs, err := readPolicyRules(db.db)
	db.record(err)
	if rs == nil {
		rs = []policy.Rule{}
	}
	now := time.Now().UnixMilli()
	out := rs[:0]
	for _, r := range rs {
		if r.UntilMS > 0 && r.UntilMS <= now {
			continue
		}
		out = append(out, r)
	}
	return out
}

func seedPolicy(tx *sql.Tx) error {
	defaults := []policy.Rule{
		{ID: policy.StarterSSH, Name: "SSH", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 22}},
		{ID: "default-dns-udp", Name: "DNS UDP", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 53}},
		{ID: "default-dns-tcp", Name: "DNS TCP", Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 53}},
		{ID: "default-ntp", Name: "NTP", Match: policy.Match{Direction: "out", Protocol: "udp", RemotePort: 123}},
		{ID: "default-ubuntu", Name: "Репозиторий Ubuntu", Match: policy.Match{Networks: []string{"185.125.190.0/24", "91.189.91.0/24"}}},
	}
	for i, r := range defaults {
		r.Enabled = true
		r.Action = "allow"
		r.Version = 1
		r.Order = 1000 + i
		raw, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES(?,?,?,?)", r.ID, 1, r.Order, string(raw)); e != nil {
			return e
		}
	}
	return nil
}

func ipToPrefix(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		if p.Addr().Is4In6() {
			return "", false
		}
		return p.String(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits).String(), true
}

func isServiceRuleID(id string) bool {
	return strings.HasPrefix(id, "monitor-svc-") || strings.HasPrefix(id, "park-svc-")
}

func findDuplicateRule(tx *sql.Tx, rule policy.Rule) (string, error) {
	want := ruleFingerprint(rule)
	rows, err := tx.Query("SELECT rule_id, payload FROM policy_rules")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return "", err
		}
		if id == rule.ID {
			continue
		}
		var other policy.Rule
		if json.Unmarshal([]byte(raw), &other) != nil {
			continue
		}
		if ruleFingerprint(other) == want {
			if other.Name != "" {
				return other.Name, nil
			}
			return id, nil
		}
	}
	return "", rows.Err()
}

func ruleFingerprint(r policy.Rule) string {
	hs := append([]string{}, r.Hosts...)
	sort.Strings(hs)
	ex := append([]string{}, r.Except...)
	sort.Strings(ex)
	nets := append([]string{}, r.Match.Networks...)
	sort.Strings(nets)
	names := append([]string{}, r.Match.Names...)
	sort.Strings(names)
	var binds []string
	for _, b := range r.Match.Bindings {
		uid := ""
		if b.UID != nil {
			uid = strconv.Itoa(*b.UID)
		}
		binds = append(binds, strings.Join([]string{b.Host, b.Cgroup, b.Path, b.Name, uid}, "\x1f"))
	}
	sort.Strings(binds)
	return strings.Join([]string{
		r.Action, r.GroupID, fmt.Sprint(r.Once),
		strings.Join(hs, ","), strings.Join(ex, ","),
		r.Match.Direction, r.Match.Protocol, r.Match.Process, r.Match.Cgroup,
		strconv.Itoa(r.Match.LocalPort), strconv.Itoa(r.Match.RemotePort), strconv.Itoa(r.Match.AnyPort),
		strings.Join(nets, ","), strings.Join(names, ","), strings.Join(binds, ";"),
	}, "|")
}
