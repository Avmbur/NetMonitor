package server

import (
	"database/sql"
	"net/netip"
	"strings"

	"netmonitor/internal/policy"
	"netmonitor/internal/store"
)

type hostDecision struct {
	never  []netip.Prefix
	bans   []policy.Rule
	groups []policy.Rule
	rules  []policy.Rule
	mode   string
	plain  string // режим без карантина; карантин его не затирает
	storm  bool
}

// hostMode — режим хоста без карантина: свой, а если он пустой или «парк», то режим парка.
func hostMode(ctrl hostControl, park string) string {
	if ctrl.Mode != "" && ctrl.Mode != "park" {
		return ctrl.Mode
	}
	if park == "" {
		return "learn"
	}
	return park
}

func loadHostDecision(db policyReader, host string, never []netip.Prefix, park string) (hostDecision, error) {
	d := hostDecision{never: never}
	ctrl, err := readControl(db, host)
	if err != nil {
		return d, err
	}
	d.plain = hostMode(ctrl, park)
	d.mode = d.plain
	if ctrl.Quarantine {
		d.mode = "quarantine"
	}
	d.storm = d.mode != "quarantine" && stormActive(db, host, store.NowMS())
	bans, err := readBans(db, `WHERE state='active' AND (expires_at_ms IS NULL OR expires_at_ms>?)`, store.NowMS())
	if err != nil {
		return d, err
	}
	for _, b := range bans {
		if b.covers(host) {
			d.bans = append(d.bans, b.rule())
		}
	}
	d.groups, err = hostGroups(db, host)
	if err != nil {
		return d, err
	}
	d.rules, err = hostRules(db, host)
	return d, err
}

func (d hostDecision) explain(c policy.Contact, now int64) (name, state, detail string) {
	name, action, state := d.resolve(c, now)
	if names := d.matchingGroupNames(c, now); len(names) > 0 {
		detail = "группы: " + strings.Join(names, ", ")
	}
	_ = action
	return name, state, detail
}

func (d hostDecision) resolve(c policy.Contact, now int64) (name, action, state string) {
	switch c.Direction {
	case "bridge", "fromhost":
		return "docker", "allow", "open"
	case "tohost":
		if d.mode == "quarantine" && !containerDNS(c) {
			return "карантин", "deny", "block"
		}
		return "docker", "allow", "open"
	}
	ip, err := netip.ParseAddr(c.RemoteIP)
	if err == nil {
		ip = ip.Unmap()
		for _, n := range d.never {
			if n.Contains(ip) {
				return "never-block", "allow", "open"
			}
		}
	}
	if dec, ok := policy.Evaluate(d.bans, c.Host, c, now); ok {
		return verdictName(d.bans, dec, "бан"), "deny", "block"
	}
	// Шторм — до групп и правил, как в nft: пропускает только адреса, прямо
	// названные в разрешающем правиле или группе (fw.stormNamed).
	if d.storm && c.Direction == "in" && !privateAddr(c.RemoteIP) && !d.stormNamed(ip) {
		return "шторм", "deny", "block"
	}
	if dec, ok := policy.Evaluate(d.groups, c.Host, c, now); ok {
		st := "open"
		if dec.Action == "deny" || dec.Action == "alert" {
			st = "block"
		}
		return verdictName(d.groups, dec, dec.ID), dec.Action, st
	}
	if dec, ok := policy.Evaluate(d.rules, c.Host, c, now); ok {
		st := "open"
		if dec.Action == "deny" {
			st = "block"
		}
		return verdictName(d.rules, dec, dec.ID), dec.Action, st
	}
	switch d.mode {
	case "block", "quarantine":
		return "блокировать", "deny", "block"
	case "learn":
		return "обучение", "learn", "block"
	default:
		return "—", "allow", "open"
	}
}

func containerDNS(c policy.Contact) bool {
	if c.RemotePort != 53 {
		return false
	}
	return c.Protocol == "" || c.Protocol == "tcp" || c.Protocol == "udp"
}

func (d hostDecision) stormNamed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, list := range [][]policy.Rule{d.groups, d.rules} {
		for _, r := range list {
			if !r.Enabled || r.Action != "allow" || r.Match.Direction == "out" {
				continue
			}
			for _, n := range r.Match.Networks {
				px, err := netip.ParsePrefix(n)
				if err != nil {
					a, e := netip.ParseAddr(n)
					if e != nil {
						continue
					}
					px = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
				}
				if px.Bits() > 0 && px.Masked().Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

func (d hostDecision) needsQuestion(c policy.Contact, now int64) bool {
	_, action, _ := d.resolve(c, now)
	if action == "alert" {
		return true
	}
	if action == "learn" {
		return true
	}
	return false
}

func (d hostDecision) matchingGroupNames(c policy.Contact, now int64) []string {
	var names []string
	seen := map[string]bool{}
	for _, g := range policy.Ordered(d.groups) {
		if !g.Active(now) || g.SpentOn(c.Host) || !g.OnHost(c.Host) || !g.Match.Matches(c) {
			continue
		}
		n := g.Name
		if n == "" {
			n = g.ID
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	return names
}

func verdictName(rs []policy.Rule, dec policy.Decision, fallback string) string {
	for _, r := range rs {
		if r.ID == dec.ID && r.Name != "" {
			return r.Name
		}
	}
	if fallback != "" {
		return fallback
	}
	return dec.ID
}

func neverPrefixes(db policyReader) []netip.Prefix {
	ss, err := policyStrings(db, "SELECT cidr FROM never_block")
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, e := netip.ParseAddr(s)
			if e != nil {
				continue
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out
}

func settingValue(db policyReader, k, fallback string) string {
	var v string
	if err := db.QueryRow("SELECT v FROM settings WHERE k=?", k).Scan(&v); err != nil || v == "" {
		return fallback
	}
	return v
}

func closeCoveredQuestions(tx *sql.Tx, host string, now int64, before ...func(string) error) error {
	rows, err := tx.Query("SELECT question_id,host_id,direction,protocol,remote_ip,COALESCE(local_port,0),COALESCE(remote_port,0),COALESCE(proc_path,''),COALESCE(proc_comm,'') FROM learn_questions WHERE status='open' AND host_id=?", host)
	if err != nil {
		return err
	}
	type row struct {
		id string
		c  policy.Contact
	}
	var qs []row
	for rows.Next() {
		var q row
		var comm string
		if err = rows.Scan(&q.id, &q.c.Host, &q.c.Direction, &q.c.Protocol, &q.c.RemoteIP, &q.c.LocalPort, &q.c.RemotePort, &q.c.Process, &comm); err != nil {
			rows.Close()
			return err
		}
		if b, e := policy.ParseIdentity(q.c.Process, q.c.Host, comm); e == nil {
			q.c.Process, q.c.Cgroup, q.c.UID = b.Path, b.Cgroup, b.UID
		}
		qs = append(qs, q)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// Политика хоста собирается только когда есть что закрывать.
	if len(qs) == 0 {
		return nil
	}
	d, err := loadHostDecision(tx, host, neverPrefixes(tx), settingValue(tx, "park_mode", "learn"))
	if err != nil {
		return err
	}
	// Карантин сам по себе не ответ. Закрытие смотрит режим, который был бы без него.
	// Шторм остаётся выключенным: в фильтре карантин его тоже гасит.
	if d.mode == "quarantine" {
		d.mode = d.plain
	}
	for _, q := range qs {
		if d.needsQuestion(q.c, now) {
			continue
		}
		_, action, _ := d.resolve(q.c, now)
		if action == "" || action == "learn" {
			continue
		}
		for _, fn := range before {
			if err := fn(q.id); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("UPDATE learn_questions SET status='answered',answer=? WHERE question_id=?", action, q.id); err != nil {
			return err
		}
	}
	return nil
}
