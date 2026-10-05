package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/store"
)

// A ban lives in the same model as a rule: the same exact conditions, the same
// server selection and one absolute expiry, addressed by its own block_id.
// Nothing here widens a condition the backend cannot execute.
type banSpec struct {
	ID        string
	Hosts     []string // nil — весь парк
	Except    []string
	RemoteIP  string
	Protocol  string
	Direction string
	Port      int // удалённый порт
	LocalPort int
	ExpiresAt int64 // 0 — бессрочно
	Escalate  int
	Reason    string
	Source    string
	CreatedBy string
}

type banRecord struct {
	banSpec
	State     string
	CreatedAt int64
	UpdatedAt int64
	RemovedAt int64
	Version   int64
	Escalate  int
}

func (b banSpec) rule() policy.Rule {
	m := policy.Match{Protocol: b.Protocol, Direction: b.Direction, RemotePort: b.Port, LocalPort: b.LocalPort}
	if m.Direction == "" {
		m.Direction = "both"
	}
	if b.RemoteIP != "" {
		if a, err := netipx.Parse(b.RemoteIP); err == nil {
			m.Networks = []string{netip.PrefixFrom(a, a.BitLen()).String()}
		}
	}
	return policy.Rule{
		ID: "ban:" + b.ID, Name: b.Reason, Enabled: true, Action: "deny",
		Hosts: b.Hosts, Except: b.Except, Match: m, UntilMS: b.ExpiresAt,
	}
}

// covers answers whether this ban reaches the host at all; the same selection
// semantics as a rule, so scope cannot mean one thing in SQL and another in nft.
func (b banSpec) covers(hostID string) bool { return b.rule().OnHost(hostID) }

func (b banSpec) targetLabel() string {
	out := b.RemoteIP
	if out == "" {
		out = "любой адрес"
	}
	proto := b.Protocol
	if proto == "" || proto == "any" {
		proto = ""
	}
	if b.Port > 0 {
		out += ":" + strconv.Itoa(b.Port)
		if proto != "" {
			out += "/" + proto
		}
	}
	if b.LocalPort > 0 {
		local := "локальный :" + strconv.Itoa(b.LocalPort)
		if proto != "" {
			local += "/" + proto
		}
		out += " · " + local
	}
	if b.Port == 0 && b.LocalPort == 0 && proto != "" {
		out += " · " + proto
	}
	switch b.Direction {
	case "in":
		out += " · вход"
	case "out":
		out += " · исход"
	}
	return out
}

// Unsupported precision is rejected, not broadened: automation never closes a
// local port, and an empty server list never means the whole park.
func validateBan(b banSpec, confirmLocalPort bool) error {
	if strings.Contains(b.RemoteIP, "/") {
		return fmt.Errorf("подсеть банится группой с политикой «блокировать»; здесь — один адрес")
	}
	if b.RemoteIP == "" && b.LocalPort == 0 {
		return fmt.Errorf("укажи адрес или локальный порт")
	}
	if b.RemoteIP != "" {
		if _, err := netipx.Parse(b.RemoteIP); err != nil {
			return fmt.Errorf("неверный адрес")
		}
	}
	if b.LocalPort > 0 {
		if b.Source != "manual" {
			return fmt.Errorf("локальный порт закрывается только вручную")
		}
		if !confirmLocalPort {
			return fmt.Errorf("закрытие локального порта подтверди явно")
		}
		if b.ExpiresAt == 0 {
			return fmt.Errorf("бан локального порта требует срока")
		}
	}
	if b.ExpiresAt < 0 {
		return fmt.Errorf("неверный срок бана")
	}
	if b.Source != "manual" && b.ExpiresAt == 0 {
		return fmt.Errorf("автоматический бан не бывает бессрочным")
	}
	if b.Hosts != nil && len(b.Hosts) == 0 {
		return fmt.Errorf("выбери серверы")
	}
	// Бан с портом по-прежнему требует протокол; «любой» с портом — только у правил.
	if (b.Port > 0 || b.LocalPort > 0) && b.Protocol != "tcp" && b.Protocol != "udp" {
		return fmt.Errorf("a port requires tcp or udp")
	}
	return policy.Executable(b.rule())
}

func scopeColumns(hosts []string) (kind string, hostID any, hostsJSON any, err error) {
	if hosts == nil {
		return "all", nil, nil, nil
	}
	raw, err := json.Marshal(hosts)
	if err != nil {
		return "", nil, nil, err
	}
	if len(hosts) == 1 {
		// A single server keeps host_id filled for the existing block indexes.
		return "host", hosts[0], string(raw), nil
	}
	return "hosts", nil, string(raw), nil
}

func readScope(kind, hostID, hostsJSON, exceptJSON string) (hosts, except []string, err error) {
	switch {
	case hostsJSON != "":
		if err = json.Unmarshal([]byte(hostsJSON), &hosts); err != nil {
			return nil, nil, err
		}
	case kind == "host" && hostID != "":
		hosts = []string{hostID}
	}
	if exceptJSON != "" {
		if err = json.Unmarshal([]byte(exceptJSON), &except); err != nil {
			return nil, nil, err
		}
	}
	return hosts, except, nil
}

const banColumns = `block_id,scope_kind,COALESCE(host_id,''),COALESCE(hosts_json,''),COALESCE(except_json,''),
	COALESCE(remote_ip,''),COALESCE(protocol,''),COALESCE(port,0),COALESCE(local_port,0),direction,
	COALESCE(expires_at_ms,0),state,reason,source,created_by,created_at_ms,COALESCE(updated_at_ms,created_at_ms),version,escalate_step,COALESCE(removed_at_ms,0)`

type rowScanner interface{ Scan(...any) error }

func scanBan(row rowScanner) (banRecord, error) {
	var b banRecord
	var kind, hostID, hostsJSON, exceptJSON string
	err := row.Scan(&b.ID, &kind, &hostID, &hostsJSON, &exceptJSON,
		&b.RemoteIP, &b.Protocol, &b.Port, &b.LocalPort, &b.Direction,
		&b.ExpiresAt, &b.State, &b.Reason, &b.Source, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt, &b.Version, &b.Escalate, &b.RemovedAt)
	if err != nil {
		return b, err
	}
	b.Hosts, b.Except, err = readScope(kind, hostID, hostsJSON, exceptJSON)
	return b, err
}

func readBan(db policyReader, id string) (banRecord, error) {
	return scanBan(db.QueryRow("SELECT "+banColumns+" FROM blocks WHERE block_id=?", id))
}

func readBans(db policyReader, where string, args ...any) ([]banRecord, error) {
	rows, err := db.Query("SELECT "+banColumns+" FROM blocks "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []banRecord
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// writeBan stores the ban with its scope and issues one command per covered
// agent. An automatic ban respects a server pause; a manual one does not.
func writeBan(tx *sql.Tx, b banSpec, now int64) (string, error) {
	kind, hostID, hostsJSON, err := scopeColumns(b.Hosts)
	if err != nil {
		return "", err
	}
	var exceptJSON any
	if len(b.Except) > 0 {
		raw, err := json.Marshal(b.Except)
		if err != nil {
			return "", err
		}
		exceptJSON = string(raw)
	}
	var expires, ip, bin, protocol, port, localPort any
	if b.ExpiresAt > 0 {
		expires = b.ExpiresAt
	}
	if b.RemoteIP != "" {
		addr, err := netipx.Parse(b.RemoteIP)
		if err != nil {
			return "", err
		}
		b.RemoteIP = netipx.Canonical(addr)
		ip, bin = b.RemoteIP, netipx.Bin16(addr)
	}
	if b.Protocol != "" && b.Protocol != "any" {
		protocol = b.Protocol
	}
	if b.Port > 0 {
		port = b.Port
	}
	if b.LocalPort > 0 {
		localPort = b.LocalPort
	}
	direction := b.Direction
	if direction == "" {
		direction = "both"
	}
	if b.ID == "" {
		b.ID = idgen.NewV7()
		if _, err := tx.Exec(
			`INSERT INTO blocks(block_id, host_id, scope_kind, hosts_json, except_json, remote_ip, remote_ip_bin,
			  protocol, port, local_port, direction, state, reason, source, created_by, created_at_ms, updated_at_ms, expires_at_ms, escalate_step)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?)`,
			b.ID, hostID, kind, hostsJSON, exceptJSON, ip, bin,
			protocol, port, localPort, direction, b.Reason, b.Source, b.CreatedBy, now, now, expires, b.Escalate,
		); err != nil {
			return "", err
		}
	} else {
		res, err := tx.Exec(
			`UPDATE blocks SET host_id=?, scope_kind=?, hosts_json=?, except_json=?, remote_ip=?, remote_ip_bin=?,
			  protocol=?, port=?, local_port=?, direction=?, reason=?, updated_at_ms=?, expires_at_ms=?, version=version+1
			 WHERE block_id=? AND state='active'`,
			hostID, kind, hostsJSON, exceptJSON, ip, bin,
			protocol, port, localPort, direction, b.Reason, now, expires, b.ID,
		)
		if err != nil {
			return "", err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", fmt.Errorf("бан уже снят или истёк")
		}
		// A changed ban must be confirmed again. Only commands the agent has not
		// seen are withdrawn; a delivered one still deserves its ACK.
		if _, err := tx.Exec("DELETE FROM commands WHERE block_id=? AND delivered_at_ms IS NULL", b.ID); err != nil {
			return "", err
		}
	}
	saved, err := readBan(tx, b.ID)
	if err != nil {
		return "", err
	}
	if err := issueBanCommands(tx, saved, now); err != nil {
		return "", err
	}
	if err := closeAlertsCoveredByBan(tx, saved, now); err != nil {
		return "", err
	}
	if _, err := syncAttackIP(tx, saved.RemoteIP, now); err != nil {
		return "", err
	}
	return b.ID, bumpTrusted(tx)
}

// Догон при старте: на тревогу могли ответить баном раньше, чем монитор
// научился её закрывать. Сверяем живые тревоги с живыми банами один раз.
func (s *Server) reconcileAlertsWithBans() error {
	now := store.NowMS()
	return s.st.Update(func(tx *sql.Tx) error {
		bans, err := readBans(tx, "WHERE state='active' AND remote_ip IS NOT NULL AND (expires_at_ms IS NULL OR expires_at_ms>?)", now)
		if err != nil {
			return err
		}
		for _, b := range bans {
			if err := closeAlertsCoveredByBan(tx, b, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// Тревога про адрес живёт, пока адрес не отсечён. Поставили или продлили бан,
// покрывающий её сервер, — вопрос закрыт: строка уходит в историю, меню
// перестаёт мигать, сирена замолкает. «Бан сняли руками» сюда не входит: у неё
// свой ответ — вернуть бан.
func closeAlertsCoveredByBan(tx *sql.Tx, b banRecord, now int64) error {
	if b.RemoteIP == "" || b.State != "active" {
		return nil
	}
	rows, err := tx.Query(
		`SELECT a.alert_id, a.host_id, a.rule_id FROM alerts a
		 JOIN alert_refs r ON r.alert_id=a.alert_id AND r.ref_kind='ip' AND r.ref_id=?
		 WHERE a.closed_at_ms IS NULL AND a.rule_id IN ('scan-cap','ssh-cap','persist')`,
		b.RemoteIP,
	)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, host, rule string
		if err = rows.Scan(&id, &host, &rule); err != nil {
			rows.Close()
			return err
		}
		// «Вернулся после 7 суток» ждёт решения навсегда: срочный бан — это
		// та же лестница, что уже не помогла.
		if rule == "persist" && b.ExpiresAt != 0 {
			continue
		}
		if b.covers(host) {
			ids = append(ids, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	by, note := "auto", "адрес забанен"
	if b.CreatedBy == "adm" || b.CreatedBy == "cli" {
		by = "adm"
		note = "забанил"
	}
	if b.ExpiresAt == 0 {
		note += " навсегда"
	}
	for _, id := range ids {
		if _, err := closeAlert(tx, id, by, note, now); err != nil {
			return err
		}
	}
	return nil
}

func issueBanCommands(tx *sql.Tx, b banRecord, now int64) error {
	agents, err := scopeAgents(tx, b.banSpec)
	if err != nil {
		return err
	}
	for _, a := range agents {
		if b.Source != "manual" {
			c, err := readControl(tx, a.host)
			if err != nil {
				return err
			}
			// A paused server collects the ban as a pause, not as policy.
			if c.paused(now) {
				if _, err = tx.Exec("INSERT OR IGNORE INTO block_pause(agent_id,block_id,paused_at_ms) VALUES(?,?,?)", a.id, b.ID, now); err != nil {
					return err
				}
				continue
			}
		}
		if err := ensureBanCommand(tx, b, a.id, now); err != nil {
			return err
		}
	}
	return nil
}

// Also called from poll so agents trusted after creation can confirm the ban.
func ensureBanCommand(tx *sql.Tx, b banRecord, agentID string, now int64) error {
	payload, err := json.Marshal(map[string]any{
		"op": "ban", "ip": b.RemoteIP, "proto": b.Protocol, "direction": b.Direction,
		"port": b.Port, "local_port": b.LocalPort, "block_id": b.ID,
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO commands(command_id,agent_id,kind,payload,block_id,block_version,created_at_ms)
		 VALUES(?,?,'ban',?,?,?,?)
		 ON CONFLICT(agent_id,block_id,block_version) WHERE kind='ban' DO NOTHING`,
		idgen.NewV7(), agentID, string(payload), b.ID, b.Version, now)
	return err
}

type agentRef struct{ id, host string }

func scopeAgents(db policyReader, b banSpec) ([]agentRef, error) {
	rows, err := db.Query("SELECT agent_id,COALESCE(host_id,'') FROM agents WHERE trust_state='trusted' ORDER BY agent_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agentRef
	for rows.Next() {
		var a agentRef
		if err := rows.Scan(&a.id, &a.host); err != nil {
			return nil, err
		}
		if b.covers(a.host) {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// Confirmations are the acknowledged ban commands of the whole park, read once
// per screen: a list of forty bans must not turn into a query per agent.
type banConfirmations struct {
	agents []agentRef
	acked  map[string]map[string]int64 // бан → агент → версия подтверждённого бана
}

func readConfirmations(db policyReader) (banConfirmations, error) {
	c := banConfirmations{acked: map[string]map[string]int64{}}
	rows, err := db.Query("SELECT agent_id,COALESCE(host_id,'') FROM agents WHERE trust_state='trusted' ORDER BY agent_id")
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var a agentRef
		if err = rows.Scan(&a.id, &a.host); err != nil {
			rows.Close()
			return c, err
		}
		c.agents = append(c.agents, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return c, err
	}
	rows, err = db.Query(`SELECT c.block_id,c.agent_id,MAX(c.block_version) FROM commands c
		JOIN blocks b ON b.block_id=c.block_id AND b.version=c.block_version AND b.state='active'
		WHERE c.kind='ban' AND c.result='applied' AND c.acked_at_ms IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM block_pause p WHERE p.block_id=c.block_id AND p.agent_id=c.agent_id)
		GROUP BY c.block_id,c.agent_id`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var block, agent string
		var at int64
		if err = rows.Scan(&block, &agent, &at); err != nil {
			return c, err
		}
		if c.acked[block] == nil {
			c.acked[block] = map[string]int64{}
		}
		c.acked[block][agent] = at
	}
	return c, rows.Err()
}

// count reports only agents that confirmed this exact version of the ban.
// A delivered or stale command is not evidence of a working restriction.
func (c banConfirmations) count(b banRecord) (applied, total int) {
	applied, total, _ = c.coverage(b, nil)
	return applied, total
}

func (c banConfirmations) coverage(b banRecord, paused []string) (applied, total int, missed []string) {
	pausedOn := map[string]bool{}
	for _, h := range paused {
		pausedOn[h] = true
	}
	for _, a := range c.agents {
		if !b.covers(a.host) {
			continue
		}
		total++
		if pausedOn[a.host] {
			continue
		}
		if version, ok := c.acked[b.ID][a.id]; ok && version == b.Version {
			applied++
		} else if a.host != "" {
			missed = append(missed, a.host)
		}
	}
	return applied, total, missed
}

func readBanPauses(db policyReader) (map[string][]string, error) {
	out := map[string][]string{}
	rows, err := db.Query(`SELECT p.block_id, COALESCE(a.host_id,'') FROM block_pause p JOIN agents a ON a.agent_id=p.agent_id`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	seen := map[string]map[string]bool{}
	for rows.Next() {
		var block, host string
		if err = rows.Scan(&block, &host); err != nil {
			return out, err
		}
		if host == "" {
			continue
		}
		if seen[block] == nil {
			seen[block] = map[string]bool{}
		}
		if seen[block][host] {
			continue
		}
		seen[block][host] = true
		out[block] = append(out[block], host)
	}
	return out, rows.Err()
}

func banReasonText(reason string) string {
	if reason == "ручной" {
		return "вручную"
	}
	return reason
}

func banApplied(db policyReader, b banRecord) (applied, total int, err error) {
	c, err := readConfirmations(db)
	if err != nil {
		return 0, 0, err
	}
	applied, total = c.count(b)
	return applied, total, nil
}

// removeBan lifts exactly one ban. Another ban on the same address keeps working.
func removeBan(tx *sql.Tx, id, actor string, now int64) error {
	b, err := readBan(tx, id)
	if err == sql.ErrNoRows {
		return fmt.Errorf("бан не найден")
	}
	if err != nil {
		return err
	}
	if b.State != "active" {
		return fmt.Errorf("бан уже снят или истёк")
	}
	if _, err = tx.Exec("UPDATE blocks SET state='removed', removed_at_ms=? WHERE block_id=? AND state='active'", now, id); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM commands WHERE block_id=? AND delivered_at_ms IS NULL", id); err != nil {
		return err
	}
	agents, err := scopeAgents(tx, b.banSpec)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"op": "unban", "ip": b.RemoteIP, "block_id": id})
	if err != nil {
		return err
	}
	for _, a := range agents {
		if _, err = tx.Exec(
			`INSERT INTO commands(command_id, agent_id, kind, payload, block_id, created_at_ms) VALUES(?,?,?,?,?,?)`,
			idgen.NewV7(), a.id, "unban", string(payload), id, now,
		); err != nil {
			return err
		}
	}
	if err = auditBan(tx, actor, "снял бан", b.banSpec, now); err != nil {
		return err
	}
	if _, err = syncAttackIP(tx, b.RemoteIP, now); err != nil {
		return err
	}
	return bumpTrusted(tx)
}

func auditBan(tx *sql.Tx, actor, action string, b banSpec, now int64) error {
	detail := scopeLabel(b.Hosts, b.Except)
	if b.ExpiresAt > 0 {
		detail += " · до " + time.UnixMilli(b.ExpiresAt).UTC().Format("2006-01-02 15:04:05")
	} else {
		detail += " · навсегда"
	}
	_, err := tx.Exec(
		`INSERT INTO audit_log(audit_id, at_ms, actor, action, object, detail) VALUES(?,?,?,?,?,?)`,
		idgen.NewV7(), now, actor, action, b.targetLabel(), detail)
	return err
}

// banListFilter chooses which rows the tile asks for. The default, an empty
// view, is the live set. History is explicit and bounded.
type banListFilter struct {
	View  string
	IP    string
	Since int64
	ID    string
}

func banIPQueryOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// listBans shows the stored scope and the confirmed coverage, never the
// intention alone: «применено N из M» counts agent acknowledgements.
// Живые баны приходят всегда: по ним карточки продлевают и возвращают бан.
// Истёкшие и снятые — добавкой по запросу, фильтр адреса только для них.
func (s *Server) listBans(db *checkedRead, f banListFilter) []uiBan {
	now := store.NowMS()
	bans, err := readBans(db.db, "WHERE state='active' AND (expires_at_ms IS NULL OR expires_at_ms>?) ORDER BY created_at_ms DESC", now)
	db.record(err)
	since := f.Since
	if since <= 0 {
		since = now - 7*24*time.Hour.Milliseconds()
	}
	var where string
	switch f.View {
	case "expired":
		where = "state='expired' AND COALESCE(expires_at_ms, created_at_ms)>=?"
	case "removed":
		where = "state='removed' AND COALESCE(removed_at_ms, updated_at_ms, created_at_ms)>=?"
	}
	if where != "" {
		args := []any{since}
		if ip := strings.TrimSpace(f.IP); banIPQueryOK(ip) {
			where += " AND instr(remote_ip,?)>0"
			args = append(args, ip)
		}
		old, err := readBans(db.db, "WHERE "+where+" ORDER BY created_at_ms DESC LIMIT 300", args...)
		db.record(err)
		bans = append(bans, old...)
	}
	if f.ID != "" {
		seen := false
		for _, b := range bans {
			seen = seen || b.ID == f.ID
		}
		if !seen {
			if b, err := readBan(db.db, f.ID); err == nil {
				bans = append(bans, b)
			} else if err != sql.ErrNoRows {
				db.record(err)
			}
		}
	}
	confirmations, err := readConfirmations(db.db)
	db.record(err)
	pauses, err := readBanPauses(db.db)
	db.record(err)
	out := []uiBan{}
	for _, b := range bans {
		u := uiBan{
			ID: b.ID, IP: b.RemoteIP, Target: b.targetLabel(), State: banShownState(b, now), UntilMS: b.ExpiresAt,
			Reason: banReasonText(b.Reason), Source: b.Source, Protocol: b.Protocol, Direction: b.Direction,
			Port: b.Port, LocalPort: b.LocalPort, Except: b.Except, Persist: b.Escalate > 0,
			Until: "навсегда", CreatedMS: b.CreatedAt, RemovedMS: b.RemovedAt,
		}
		if b.ExpiresAt > 0 {
			u.Until = time.UnixMilli(b.ExpiresAt).Local().Format("2006-01-02 15:04:05")
		}
		u.Hosts = json.RawMessage(`"all"`)
		if b.Hosts != nil {
			raw, err := json.Marshal(b.Hosts)
			db.record(err)
			if err == nil {
				u.Hosts = raw
			}
		}
		if b.State == "active" {
			u.Applied, u.Total, u.Missed = confirmations.coverage(b, pauses[b.ID])
			u.Paused = pauses[b.ID]
		}
		out = append(out, u)
	}
	return out
}

func scopeLabel(hosts, except []string) string {
	if hosts == nil {
		if len(except) == 0 {
			return "все серверы"
		}
		return "все кроме " + strings.Join(except, ", ")
	}
	return strings.Join(hosts, ", ")
}
