package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
)

type uiGroup struct {
	Op      string          `json:"op,omitempty"`
	IDs     []string        `json:"ids,omitempty"`
	Order   int             `json:"order"`
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Policy  string          `json:"policy"`
	Members string          `json:"members"`
	Hosts   json.RawMessage `json:"hosts"`
	Mute    bool            `json:"mute"`
	Except  []string        `json:"except"`
	Count   int             `json:"count"`
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	var in uiGroup
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	if in.Op == "order" || in.Op == "delete" || in.Op == "member" {
		s.groupOperation(w, in)
		return
	}
	if in.Op != "" {
		http.Error(w, "неверное действие", 400)
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		http.Error(w, "имя", 400)
		return
	}
	switch in.Policy {
	case "allow", "watch", "observe", "signal", "alert", "block":
	default:
		http.Error(w, "неверная политика группы", 400)
		return
	}
	hosts, scopeErr := parseScope(in.Hosts, "")
	if scopeErr != nil {
		http.Error(w, scopeErr.Error(), 400)
		return
	}

	if len(in.Hosts) == 0 {
		in.Hosts = json.RawMessage(`"all"`)
	}
	pol := mapGroupPolicy(in.Policy)
	// Ссылки качаем до транзакции: адрес вписывает агент монитора, а его
	// подтверждение тоже пишется в базу и ждало бы конца этой транзакции.
	fetched := map[string][]string{}
	for _, line := range strings.Split(in.Members, "\n") {
		line = strings.TrimSpace(line)
		if _, done := fetched[line]; done || !memberURL(line) {
			continue
		}
		items, err := fetchMemberList(r.Context(), line, s.admitOnMonitor)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fetched[line] = items
	}
	now := store.NowMS()
	err := s.st.Update(func(tx *sql.Tx) error {
		for _, h := range append(append([]string{}, hosts...), in.Except...) {
			var n int
			if err := tx.QueryRow("SELECT count(*) FROM hosts WHERE host_id=?", h).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("неизвестный сервер")
			}
		}
		id := strings.TrimSpace(in.ID)
		if id == "" {
			id = idgen.NewV7()
		}
		mute := 0
		if in.Mute {
			mute = 1
		}
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ip_groups WHERE group_id=?`, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 && in.ID != "" {
			return fmt.Errorf("группа уже удалена")
		}
		if n == 0 {
			if _, err := tx.Exec(
				`INSERT INTO ip_groups(group_id, name, policy, mute_alerts, created_at_ms) VALUES(?,?,?,?,?)`,
				id, strings.TrimSpace(in.Name), pol, mute, now,
			); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(
				`UPDATE ip_groups SET name=?, policy=?, mute_alerts=? WHERE group_id=?`,
				strings.TrimSpace(in.Name), pol, mute, id,
			); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM ip_group_members WHERE group_id=?`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM ip_group_patterns WHERE group_id=?`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM ip_group_host_excl WHERE group_id=?`, id); err != nil {
				return err
			}
		}

		for _, line := range strings.Split(in.Members, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			items, src, err := expandMember(line, fetched)
			if err != nil {
				return err
			}
			for _, item := range items {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				if isNameMask(item) {
					if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_group_patterns(group_id, pattern) VALUES(?,?)`, id, strings.ToLower(item)); err != nil {
						return err
					}
					continue
				}
				p, err := parseMember(item)
				if err != nil {
					return fmt.Errorf("состав %s: %w", item, err)
				}
				lo, hi := netipx.PrefixBinRange(p)
				if _, err := tx.Exec(
					`INSERT OR IGNORE INTO ip_group_members(group_id, ip_lo_bin, ip_hi_bin, cidr, source, added_at_ms) VALUES(?,?,?,?,?,?)`,
					id, lo, hi, p.String(), src, now,
				); err != nil {
					return err
				}
			}
		}

		if _, err := tx.Exec("UPDATE ip_groups SET hosts_json=?,sort_order=? WHERE group_id=?", string(in.Hosts), in.Order, id); err != nil {
			return err
		}
		for _, ex := range in.Except {
			if ex == "" {
				continue
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_group_host_excl(group_id, host_id) VALUES(?,?)`, id, ex); err != nil {
				return err
			}
		}
		if err := answerGroupQuestions(tx, now); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "adm", "сохранил группу", id); err != nil {
			return err
		}
		in.ID = id
		if _, err := reconcileAttackGroup(tx, now); err != nil {
			return err
		}
		return bumpTrusted(tx)
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]string{"ok": "1", "id": in.ID})
}

func mapGroupPolicy(p string) string {
	switch p {
	case "watch", "observe":
		return "observe"
	case "signal", "alert":
		return "alert"
	case "block":
		return "block"
	default:
		return "allow"
	}
}

func uiPolicy(p string) string {
	switch p {
	case "observe":
		return "watch"
	case "alert":
		return "signal"
	default:
		return p
	}
}

func isNameMask(s string) bool {
	if strings.Contains(s, "*") {
		return true
	}
	if strings.Contains(s, "/") {
		return false
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.IsValid() {
		return false
	}
	return strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func parseMember(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netipx.Parse(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits), nil
}

func (s *Server) listGroups(db *checkedRead) []uiGroup {
	out := []uiGroup{}
	rows, err := db.Query(`SELECT group_id, name, policy, mute_alerts FROM ip_groups ORDER BY sort_order, name`)
	if err != nil {
		return out
	}
	defer rows.Close()
	type row struct {
		id, name, pol string
		mute          int
	}
	var gs []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.name, &r.pol, &r.mute) == nil {
			gs = append(gs, r)
		}
	}
	rows.Close()
	for _, g := range gs {
		ug := uiGroup{ID: g.id, Name: g.name, Policy: uiPolicy(g.pol), Hosts: json.RawMessage(`"all"`), Mute: g.mute != 0}
		var lines []string
		mr, err := db.Query(`SELECT cidr FROM ip_group_members WHERE group_id=?`, g.id)
		if err == nil {
			for mr.Next() {
				var c string
				if mr.Scan(&c) == nil {
					lines = append(lines, c)
				}
			}
			mr.Close()
		}
		pr, err := db.Query(`SELECT pattern FROM ip_group_patterns WHERE group_id=?`, g.id)
		if err == nil {
			for pr.Next() {
				var p string
				if pr.Scan(&p) == nil {
					lines = append(lines, p)
				}
			}
			pr.Close()
		}
		var scope string
		db.QueryRow("SELECT hosts_json,sort_order FROM ip_groups WHERE group_id=?", g.id).Scan(&scope, &ug.Order)
		ug.Hosts = json.RawMessage(scope)
		ug.Members = strings.Join(lines, "\n")
		ug.Count = len(lines)
		er, err := db.Query(`SELECT host_id FROM ip_group_host_excl WHERE group_id=?`, g.id)
		if err == nil {
			for er.Next() {
				var h string
				if er.Scan(&h) == nil {
					ug.Except = append(ug.Except, h)
				}
			}
			er.Close()
		}
		out = append(out, ug)
	}
	return out
}

// policyReader lets one poll read a consistent snapshot across all policy tables.
type policyReader interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func policyStrings(db policyReader, q string, args ...any) ([]string, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func resolvePattern(db policyReader, pat string) ([]string, error) {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return nil, nil
	}
	if strings.HasPrefix(pat, "*.") {
		suf := strings.TrimPrefix(pat, "*")
		return policyStrings(db, `SELECT DISTINCT ip FROM dns_seen WHERE name=? OR name LIKE ?`, strings.TrimPrefix(pat, "*."), "%"+suf)
	}
	return policyStrings(db, `SELECT DISTINCT ip FROM dns_seen WHERE name=?`, pat)
}

func patternMatches(name, pat string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return false
	}
	if strings.HasPrefix(pat, "*.") {
		suf := strings.TrimPrefix(pat, "*")
		return name == strings.TrimPrefix(pat, "*.") || strings.HasSuffix(name, suf)
	}
	return name == pat
}

func (s *Server) groupOperation(w http.ResponseWriter, in uiGroup) {
	err := s.st.Update(func(tx *sql.Tx) error {
		switch in.Op {
		case "member":
			if strings.TrimSpace(in.ID) == "" {
				return fmt.Errorf("группа")
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM ip_groups WHERE group_id=?`, in.ID).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("группа уже удалена")
			}
			line := strings.TrimSpace(in.Members)
			if i := strings.IndexByte(line, '\n'); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line == "" {
				return fmt.Errorf("адрес")
			}
			now := store.NowMS()
			if isNameMask(line) {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_group_patterns(group_id, pattern) VALUES(?,?)`, in.ID, strings.ToLower(line)); err != nil {
					return err
				}
				break
			}
			p, err := parseMember(line)
			if err != nil {
				return fmt.Errorf("состав %s: %w", line, err)
			}
			lo, hi := netipx.PrefixBinRange(p)
			if _, err := tx.Exec(
				`INSERT OR IGNORE INTO ip_group_members(group_id, ip_lo_bin, ip_hi_bin, cidr, source, added_at_ms) VALUES(?,?,?,?,?,?)`,
				in.ID, lo, hi, p.String(), "ui", now,
			); err != nil {
				return err
			}
		case "delete":
			if in.ID == attackGroupID {
				return fmt.Errorf("служебная группа")
			}
			// Deleting membership must not turn a rule into an unrestricted address match.
			rs, err := readPolicyRules(tx)
			if err != nil {
				return err
			}
			for _, r := range rs {
				if r.GroupID == in.ID {
					return fmt.Errorf("группа используется правилом: %s", r.Name)
				}
			}
			for _, table := range []string{"ip_group_members", "ip_group_patterns", "ip_group_host_excl", "ip_groups"} {
				if _, err := tx.Exec("DELETE FROM "+table+" WHERE group_id=?", in.ID); err != nil {
					return err
				}
			}
		case "order":
			ids, err := policyStrings(tx, "SELECT group_id FROM ip_groups")
			if err != nil {
				return err
			}
			if len(ids) != len(in.IDs) {
				return fmt.Errorf("список групп изменился")
			}
			seen := map[string]bool{}
			for _, id := range ids {
				seen[id] = true
			}
			for i, id := range in.IDs {
				if !seen[id] {
					return fmt.Errorf("список групп изменился")
				}
				delete(seen, id)
				if _, err := tx.Exec("UPDATE ip_groups SET sort_order=? WHERE group_id=?", i, id); err != nil {
					return err
				}
			}
		}
		if err := answerGroupQuestions(tx, store.NowMS()); err != nil {
			return err
		}
		if _, err := reconcileAttackGroup(tx, store.NowMS()); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), "adm", "группа: "+in.Op, in.ID); err != nil {
			return err
		}
		return bumpTrusted(tx)
	})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
func answerGroupQuestions(tx *sql.Tx, now int64) error {
	rows, err := tx.Query("SELECT question_id,host_id,direction,protocol,remote_ip,COALESCE(local_port,0),COALESCE(remote_port,0) FROM learn_questions WHERE status='open'")
	if err != nil {
		return err
	}
	type q struct {
		id, host string
		c        policy.Contact
	}
	var qs []q
	for rows.Next() {
		var x q
		if err = rows.Scan(&x.id, &x.host, &x.c.Direction, &x.c.Protocol, &x.c.RemoteIP, &x.c.LocalPort, &x.c.RemotePort); err != nil {
			rows.Close()
			return err
		}
		qs = append(qs, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, x := range qs {
		gs, err := hostGroups(tx, x.host)
		if err != nil {
			return err
		}
		d, ok := policy.Evaluate(gs, x.host, x.c, now)
		if !ok || d.Action == "alert" {
			continue
		}
		if _, err = tx.Exec("UPDATE learn_questions SET status='answered',answer=? WHERE question_id=?", d.Action, x.id); err != nil {
			return err
		}
	}
	return nil
}

func memberURL(line string) bool {
	return strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "http://")
}

func expandMember(line string, fetched map[string][]string) ([]string, string, error) {
	if memberURL(line) {
		items, ok := fetched[line]
		if !ok {
			return nil, "url", fmt.Errorf("импорт %s: список не скачан", line)
		}
		return items, "url", nil
	}
	path := line
	if strings.HasPrefix(line, "file://") {
		path = strings.TrimPrefix(line, "file://")
		if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		items, err := readMemberFile(path)
		return items, "file", err
	}
	if looksLikeMemberFile(line) {
		items, err := readMemberFile(line)
		return items, "file", err
	}
	return []string{line}, "ui", nil
}

func looksLikeMemberFile(line string) bool {
	if _, err := netip.ParsePrefix(line); err == nil {
		return false
	}
	if _, err := netip.ParseAddr(line); err == nil {
		return false
	}
	st, err := os.Stat(line)
	return err == nil && !st.IsDir()
}

// fetchMemberList качает список по ссылке. HTTPS идёт через служебное правило
// nmserver: адрес ссылки вписывается в фильтр до соединения.
func fetchMemberList(ctx context.Context, url string, admit svcnet.AdmitFunc) ([]string, error) {
	cl := svcnet.ImportClient(admit, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("импорт %s: %w", url, err)
	}
	res, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("импорт %s: %w", url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("импорт %s: HTTP %d", url, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseMemberList(url, body)
}

func readMemberFile(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("импорт %s: %w", path, err)
	}
	return parseMemberList(path, body)
}

func parseMemberList(src string, body []byte) ([]string, error) {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("импорт %s: пустой список", src)
	}
	return out, nil
}

// refreshDNS runs before inserting the DNS observation, in the same savepoint.
func refreshDNS(tx *sql.Tx, ev protocol.Event) error {
	var p protocol.DNSPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	if p.Kind == "ptr" {
		return nil
	}
	ok, err := dnsTouchesPatterns(tx, p.Name)
	if err != nil || !ok {
		return err
	}
	fresh, err := dnsPairFresh(tx, p)
	if err != nil || !fresh {
		return err
	}
	return bumpTrusted(tx)
}

// dnsPairFresh checks the global pair before insertion. Event timestamps and
// the reporting host do not affect whether policy addresses have changed.
func dnsPairFresh(tx *sql.Tx, p protocol.DNSPayload) (bool, error) {
	ip, err := netipx.Parse(p.IP)
	if err != nil {
		return false, err
	}
	name := strings.ToLower(strings.TrimSuffix(p.Name, "."))
	var exists bool
	err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM dns_seen WHERE name=? AND ip_bin=?)",
		name, netipx.Bin16(ip)).Scan(&exists)
	return !exists, err
}

func dnsTouchesPatterns(tx *sql.Tx, name string) (bool, error) {
	pats, err := policyStrings(tx, "SELECT DISTINCT pattern FROM ip_group_patterns")
	if err != nil {
		return false, err
	}
	for _, p := range pats {
		if patternMatches(name, p) {
			return true, nil
		}
	}
	rows, err := tx.Query(`SELECT payload FROM policy_rules`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		var r policy.Rule
		if json.Unmarshal([]byte(raw), &r) != nil {
			continue
		}
		for _, n := range r.Match.Names {
			if patternMatches(name, n) {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}
