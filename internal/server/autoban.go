package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/ingest"
	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
)

func autoban(tx *sql.Tx, ag ingest.Agent, ev protocol.Event, now int64) error {
	if ev.Kind == "scan" || ev.Kind == "ssh" {
		if ag.DeliveryLane == "history" || ev.ObservedAtMS > 0 && now-ev.ObservedAtMS > 60_000 {
			return nil
		}
		c, err := readControl(tx, ag.HostID)
		if err != nil {
			return err
		}
		if c.paused(now) {
			return nil
		}
	}
	switch ev.Kind {
	case "health":
		var p protocol.HealthPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.Kind == "firewall_restored" {
			_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, ag.ID, "восстановлен firewall", ag.HostID)
			return err
		}

	case "scan":
		var p protocol.ScanPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if hit, err := neverHitIP(tx, p.IP); err != nil || hit {
			return err
		}
		attempts := p.Attempts
		if len(attempts) == 0 {
			for _, port := range p.Ports {
				attempts = append(attempts, protocol.ScanAttempt{Port: port})
			}
		}
		remaining := map[int]bool{}
		for _, a := range attempts {
			ok, err := ordinaryAllow(tx, ag.HostID, policy.Contact{RemoteIP: p.IP, Protocol: a.Protocol, Direction: "in", LocalPort: a.Port}, now)
			if err != nil {
				return err
			}
			if !ok {
				remaining[a.Port] = true
			}
		}
		if len(remaining) < 5 {
			return nil
		}
		if err := banInTx(tx, p.IP, ag.HostID, true, "скан портов", "scan", now); err != nil {
			return err
		}
		return stormCheck(tx, ag.HostID, "scan", now)
	case "ssh":
		var p protocol.SSHPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if hit, err := neverHitIP(tx, p.RemoteIP); err != nil || hit {
			return err
		}
		for _, port := range hostSSHPorts(tx, ag.HostID) {
			if allowed, err := allowForAddress(tx, ag.HostID, policy.Contact{RemoteIP: p.RemoteIP, Direction: "in", Protocol: "tcp", LocalPort: port}, now); err != nil || allowed {
				return err
			}
		}
		var n int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM ssh_failures WHERE host_id=? AND remote_ip=? AND observed_at_ms>?`,
			ag.HostID, p.RemoteIP, now-10*60*1000,
		).Scan(&n); err != nil {
			return err
		}
		if n < 5 {
			return nil
		}
		if err := banInTx(tx, p.RemoteIP, ag.HostID, false, "перебор SSH", "ssh", now); err != nil {
			return err
		}
		return stormCheck(tx, ag.HostID, "ssh", now)
	}
	return nil
}

func neverHitIP(tx *sql.Tx, ip string) (bool, error) {
	a, err := netipx.Parse(ip)
	if err != nil {
		return false, err
	}
	b := netipx.Bin16(a)
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM never_block WHERE ip_lo_bin<=? AND ip_hi_bin>=?`,
		b, b,
	).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	host, err := settingTx(tx, "listen_host")
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if host != "" {
		if m, err := netip.ParseAddr(host); err == nil && m.Unmap() == a.Unmap() {
			return true, nil
		}
	}
	return false, nil
}

func settingTx(tx *sql.Tx, k string) (string, error) {
	var v string
	err := tx.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v, err
}

func raiseAlert(tx *sql.Tx, hostID, rule, summary string, now int64, ips ...string) error {
	key := rule + "/" + hostID
	if rule == "persist" && len(ips) > 0 && ips[0] != "" {
		key = rule + "/" + hostID + "/" + ips[0]
	}
	return raiseAlertDedup(tx, hostID, rule, key, summary, now, ips...)
}

func raiseAlertDedup(tx *sql.Tx, hostID, rule, key, summary string, now int64, ips ...string) error {
	var aid string
	err := tx.QueryRow(`SELECT alert_id FROM alerts WHERE dedup_key=? AND closed_at_ms IS NULL`, key).Scan(&aid)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if aid == "" {
		aid = idgen.NewV7()
		if _, err = tx.Exec(
			`INSERT INTO alerts(alert_id, rule_id, rule_version, host_id, dedup_key, opened_at_ms, severity, summary)
			 VALUES(?,?,1,?,?,?,'high',?)`,
			aid, rule, hostID, key, now, summary,
		); err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail) VALUES(?,?,?,?,?,?)`,
			idgen.NewV7(), now, "auto", "тревога: "+summary, aid, ""); err != nil {
			return err
		}
	} else if _, err = tx.Exec(`UPDATE alerts SET summary=? WHERE alert_id=?`, summary, aid); err != nil {
		return err
	}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO alert_refs(alert_id,ref_kind,ref_id) VALUES(?,'ip',?)`, aid, ip); err != nil {
			return err
		}
	}
	return nil
}

// An automatic ban never carries a local port and never invents a server
// selection: it is either this server or the whole park.
var ladder = []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// exhausted — адрес вернулся уже после последней ступени (7 суток): лестнице
// расти некуда, дальше решает админ.
func nextLadder(tx *sql.Tx, ip, source string) (step int, ttl time.Duration, exhausted bool, err error) {
	var prev sql.NullInt64
	err = tx.QueryRow(
		`SELECT MAX(escalate_step) FROM blocks WHERE remote_ip=? AND source=? AND state='expired'`,
		ip, source,
	).Scan(&prev)
	if err != nil {
		return 0, ladder[0], false, err
	}
	if prev.Valid {
		step = int(prev.Int64) + 1
	}
	if step >= len(ladder) {
		step = len(ladder) - 1
		exhausted = true
	}
	return step, ladder[step], exhausted, nil
}

func banInTx(tx *sql.Tx, ip, hostID string, all bool, reason, source string, now int64) error {
	addr, err := netipx.Parse(ip)
	if err != nil {
		return err
	}
	b := banSpec{RemoteIP: netipx.Canonical(addr), Direction: "both", Reason: reason, Source: source, CreatedBy: "auto"}
	if !all {
		if hostID == "" {
			return fmt.Errorf("бан на сервер без host_id")
		}
		b.Hosts = []string{hostID}
	}
	step, ttl, exhausted, err := nextLadder(tx, b.RemoteIP, source)
	if err != nil {
		return err
	}
	b.Escalate = step
	b.ExpiresAt = now + ttl.Milliseconds()
	if err = validateBan(b, false); err != nil {
		return err
	}
	// A live ban already covering this server is not repeated; another server
	// keeps its own independent decision.
	active, err := readBans(tx, "WHERE remote_ip=? AND state='active' AND (expires_at_ms IS NULL OR expires_at_ms>?)", b.RemoteIP, now)
	if err != nil {
		return err
	}
	for _, old := range active {
		// A ban of one port, protocol or direction does not cover a whole-address ban.
		if old.Port != 0 || old.LocalPort != 0 ||
			old.Protocol != "" && old.Protocol != "any" ||
			old.Direction != "" && old.Direction != "both" && old.Direction != "any" {
			continue
		}
		if b.Hosts == nil && old.Hosts == nil && len(old.Except) == 0 {
			return nil
		}
		if b.Hosts != nil && old.covers(b.Hosts[0]) {
			return nil
		}
	}
	id, err := writeBan(tx, b, now)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(
		`INSERT INTO audit_log(audit_id, at_ms, actor, action, object, detail) VALUES(?,?,?,?,?,?)`,
		idgen.NewV7(), now, "auto", reason, b.RemoteIP, source,
	); err != nil {
		return err
	}
	// Вернулся после 7 суток — отдельная тревога: забанить навсегда или нет.
	// Обычный автобан тоже в ленту: красная строка и сирена, пока карточку не закрыли.
	if exhausted {
		return raiseAlert(tx, hostID, "persist", withAlertIP(b.RemoteIP, "вернулся после бана на 7 суток"), now, b.RemoteIP)
	}
	return raiseAlertDedup(tx, hostID, source, source+"/"+id, withAlertIP(b.RemoteIP, reason), now, b.RemoteIP)
}
