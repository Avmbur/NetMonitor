package server

import (
	"database/sql"
	"strings"

	"netmonitor/internal/netipx"
	"netmonitor/internal/store"
)

// Служебная группа: бессрочные баны за скан, перебор SSH и руками.
// Политика «наблюдать» — режет сам бан. Срок или снятие бана убирает адрес.
const (
	attackGroupID   = "attacks"
	attackGroupName = "служебные - адреса атак"
)

func (s *Server) syncAttackGroup() error {
	now := store.NowMS()
	return s.st.Update(func(tx *sql.Tx) error {
		if _, err := ensureAttackGroup(tx, now); err != nil {
			return err
		}
		changed, err := reconcileAttackGroup(tx, now)
		if err != nil || !changed {
			return err
		}
		return bumpTrusted(tx)
	})
}

func reconcileAttackGroup(tx *sql.Tx, now int64) (bool, error) {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM ip_groups WHERE group_id=?`, attackGroupID).Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if _, err := tx.Exec(`UPDATE ip_groups SET name=? WHERE group_id=? AND name!=?`, attackGroupName, attackGroupID, attackGroupName); err != nil {
		return false, err
	}
	seen := map[string]bool{}
	var ips []string
	var bans []string
	add := func(ip string, ban bool) {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
		if ban {
			bans = append(bans, ip)
		}
	}
	rows, err := tx.Query(`
		SELECT DISTINCT remote_ip FROM blocks
		WHERE state='active' AND expires_at_ms IS NULL AND remote_ip IS NOT NULL AND remote_ip!=''
		  AND (source IN ('scan','ssh','manual') OR reason='ручной')`)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var ip string
		if err = rows.Scan(&ip); err != nil {
			rows.Close()
			return false, err
		}
		add(ip, true)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()
	gid, err := ensureAttackGroup(tx, now)
	if err != nil {
		return false, err
	}
	mrows, err := tx.Query(`SELECT cidr FROM ip_group_members WHERE group_id=?`, gid)
	if err != nil {
		return false, err
	}
	for mrows.Next() {
		var cidr string
		if err = mrows.Scan(&cidr); err != nil {
			mrows.Close()
			return false, err
		}
		add(strings.TrimSuffix(strings.TrimSuffix(cidr, "/32"), "/128"), false)
	}
	if err = mrows.Err(); err != nil {
		mrows.Close()
		return false, err
	}
	mrows.Close()
	changed := false
	want := map[string]bool{}
	for _, ip := range ips {
		ok, err := syncAttackIP(tx, ip, now)
		if err != nil {
			return false, err
		}
		changed = changed || ok
	}
	for _, ip := range bans {
		if p, err := parseMember(ip); err == nil {
			want[p.String()] = true
		}
	}
	extra, err := tx.Query(`SELECT cidr FROM ip_group_members WHERE group_id=?`, attackGroupID)
	if err != nil {
		return false, err
	}
	var drop []string
	for extra.Next() {
		var cidr string
		if err = extra.Scan(&cidr); err != nil {
			extra.Close()
			return false, err
		}
		if !want[cidr] {
			drop = append(drop, cidr)
		}
	}
	if err = extra.Err(); err != nil {
		extra.Close()
		return false, err
	}
	extra.Close()
	for _, cidr := range drop {
		if _, err = tx.Exec(`DELETE FROM ip_group_members WHERE group_id=? AND cidr=?`, attackGroupID, cidr); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func ensureAttackGroup(tx *sql.Tx, now int64) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT group_id FROM ip_groups WHERE group_id=?`, attackGroupID).Scan(&id)
	if err == nil {
		_, err = tx.Exec(`UPDATE ip_groups SET name=? WHERE group_id=? AND name!=?`, attackGroupName, id, attackGroupName)
		return id, err
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	_, err = tx.Exec(
		`INSERT INTO ip_groups(group_id, name, policy, mute_alerts, hosts_json, sort_order, created_at_ms) VALUES(?, ?, 'observe', 0, '"all"', 0, ?)`,
		attackGroupID, attackGroupName, now,
	)
	if err == nil {
		return attackGroupID, nil
	}
	if err = tx.QueryRow(`SELECT group_id FROM ip_groups WHERE name=?`, attackGroupName).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func syncAttackIP(tx *sql.Tx, ip string, now int64) (bool, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false, nil
	}
	addr, err := netipx.Parse(ip)
	if err != nil {
		return false, nil
	}
	ip = netipx.Canonical(addr)
	gid, err := ensureAttackGroup(tx, now)
	if err != nil {
		return false, err
	}
	var n int
	if err = tx.QueryRow(`
		SELECT COUNT(*) FROM blocks
		WHERE state='active' AND remote_ip=? AND expires_at_ms IS NULL
		  AND (source IN ('scan','ssh','manual') OR reason='ручной')`, ip).Scan(&n); err != nil {
		return false, err
	}
	p, err := parseMember(ip)
	if err != nil {
		return false, err
	}
	lo, hi := netipx.PrefixBinRange(p)
	if n > 0 {
		res, err := tx.Exec(
			`INSERT OR IGNORE INTO ip_group_members(group_id, ip_lo_bin, ip_hi_bin, cidr, source, added_at_ms) VALUES(?,?,?,?,?,?)`,
			gid, lo, hi, p.String(), "ban", now,
		)
		if err != nil {
			return false, err
		}
		got, _ := res.RowsAffected()
		if got > 0 {
			if err = answerGroupQuestions(tx, now); err != nil {
				return false, err
			}
		}
		return got > 0, nil
	}
	res, err := tx.Exec(`DELETE FROM ip_group_members WHERE group_id=? AND ip_lo_bin=? AND ip_hi_bin=?`, gid, lo, hi)
	if err != nil {
		return false, err
	}
	got, _ := res.RowsAffected()
	return got > 0, nil
}
