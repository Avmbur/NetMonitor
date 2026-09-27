package server

import (
	"database/sql"
	"net/netip"
	"strconv"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
)

// Шторм: автобан не тормозит, а за минуту на сервере встало столько банов,
// что резать по одному уже поздно. Тогда на этом сервере — при любом режиме —
// новые входы с улицы закрываются целиком, в том числе через правила «для
// всех». Проходят «Не блокировать», локальная сеть и адреса, прямо названные
// в разрешающих правилах и группах. Шторм живёт stormHold после последней
// штормовой минуты или пока админ не откроет вход.
const stormHold = 10 * 60 * 1000

var stormLevel = map[string]int{"scan": 200, "ssh": 20}

func stormKey(host string) string { return "host_storm:" + host }

func stormUntil(db policyReader, host string) int64 {
	var raw string
	if db.QueryRow(`SELECT v FROM settings WHERE k=?`, stormKey(host)).Scan(&raw) != nil {
		return 0
	}
	v, _ := strconv.ParseInt(raw, 10, 64)
	return v
}

// Улица — всё, кроме частных и локальных адресов.
func privateAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func stormMode(mode string, storm bool) string {
	switch {
	case !storm || mode == "" || mode == "quarantine":
		return mode
	case mode == "allow":
		return "shield"
	default:
		return mode + "+storm"
	}
}

func stormActive(db policyReader, host string, now int64) bool {
	return host != "" && stormUntil(db, host) > now
}

func stormCheck(tx *sql.Tx, host, source string, now int64) error {
	level := stormLevel[source]
	if host == "" || level == 0 {
		return nil
	}
	var n int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM blocks WHERE source=? AND created_by='auto' AND created_at_ms>? AND (host_id=? OR scope_kind='all')`,
		source, now-60*1000, host,
	).Scan(&n); err != nil {
		return err
	}
	if n < level {
		return nil
	}
	was := stormActive(tx, host, now)
	if _, err := tx.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		stormKey(host), strconv.FormatInt(now+stormHold, 10)); err != nil {
		return err
	}
	summary := "шторм сканов"
	if source == "ssh" {
		summary = "шторм SSH"
	}
	if err := raiseAlert(tx, host, "storm", summary, now); err != nil {
		return err
	}
	if was {
		return nil
	}
	if _, err := tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=? AND trust_state='trusted'`, host); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail) VALUES(?,?,?,?,?,?)`,
		idgen.NewV7(), now, "auto", "шторм: внешние подключения закрыты", host, strconv.Itoa(n)+" банов за минуту")
	return err
}

// Шторм кончился — вход снова по режиму сервера, тревога уходит в историю.
func (s *Server) expireStorms(now int64) error {
	return s.st.Update(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT k, v FROM settings WHERE k LIKE 'host_storm:%'`)
		if err != nil {
			return err
		}
		var hosts []string
		for rows.Next() {
			var k, v string
			if err = rows.Scan(&k, &v); err != nil {
				rows.Close()
				return err
			}
			if until, _ := strconv.ParseInt(v, 10, 64); until <= now {
				hosts = append(hosts, strings.TrimPrefix(k, "host_storm:"))
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, host := range hosts {
			if _, err = tx.Exec(`DELETE FROM settings WHERE k=?`, stormKey(host)); err != nil {
				return err
			}
			if _, err = tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=? AND trust_state='trusted'`, host); err != nil {
				return err
			}
			if _, err = closeAlertsWhere(tx, "auto", "шторм стих", now, `rule_id='storm' AND host_id=?`, host); err != nil {
				return err
			}
			if _, err = tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)`,
				idgen.NewV7(), now, "auto", "шторм стих", host); err != nil {
				return err
			}
		}
		return nil
	})
}

// Потолка автобана больше нет: старые тревоги «автобан отключён» закрываем
// при старте, отвечать на них нечем.
func (s *Server) closeCapAlerts() error {
	now := store.NowMS()
	return s.st.Update(func(tx *sql.Tx) error {
		_, err := closeAlertsWhere(tx, "auto", "потолка автобана больше нет", now, `rule_id IN ('scan-cap','ssh-cap')`)
		return err
	})
}
