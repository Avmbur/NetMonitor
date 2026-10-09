package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"netmonitor/internal/idgen"
)

// Лента тревог. Тревога не исчезает: активная — красная; закрытая — жёлтая,
// пока админ её не видел, и зелёная, когда видел (закрыл карточку) или сам
// ответил. Каждое открытие и закрытие — строка журнала «тревога…».

const (
	// Агент замолчал: столько тишины, и тревога.
	silentAfterMS = 2 * 60 * 1000
)

// closeAlert закрывает одну живую тревогу. by — кто закрыл: adm — ответ
// админа (сразу зелёная), auto — причина ушла сама (жёлтая, пока не видел).
func closeAlert(tx *sql.Tx, id, by, note string, now int64) (bool, error) {
	seen := any(nil)
	if by == "adm" {
		seen = now
	}
	res, err := tx.Exec(`UPDATE alerts SET closed_at_ms=?, closed_by=?, close_note=?, seen_at_ms=COALESCE(seen_at_ms,?)
		WHERE alert_id=? AND closed_at_ms IS NULL`, now, by, note, seen, id)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	actor := by
	if actor == "" {
		actor = "auto"
	}
	_, err = tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail) VALUES(?,?,?,?,?,?)`,
		idgen.NewV7(), now, actor, "тревога закрыта: "+note, id, "")
	return err == nil, err
}

// closeAlertsWhere закрывает все живые тревоги под условие.
func closeAlertsWhere(tx *sql.Tx, by, note string, now int64, where string, args ...any) (int, error) {
	rows, err := tx.Query(`SELECT alert_id FROM alerts WHERE closed_at_ms IS NULL AND (`+where+`)`, args...)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		ok, err := closeAlert(tx, id, by, note, now)
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

func markAlertSeen(tx *sql.Tx, id string, now int64) error {
	_, err := tx.Exec(`UPDATE alerts SET seen_at_ms=? WHERE alert_id=? AND seen_at_ms IS NULL`, now, id)
	return err
}

// sweepAlerts сверяет тревоги с тем, что есть на самом деле: открывает
// «агент замолчал» и «политика не применилась», закрывает тревоги, причина
// которых ушла сама (диск освободили, клон разобран, агент вернулся).
func (s *Server) sweepAlerts(now int64) error {
	seen := map[string]int64{}
	{
		s.pulseMu.Lock()
		for host, at := range s.hostSeen {
			seen[host] = at
		}
		s.pulseMu.Unlock()
	}
	return s.st.Update(func(tx *sql.Tx) error {
		return sweepAlertsTx(tx, now, s.startedMS, seen)
	})
}

// silenceAt — момент, с которым сравнивают порог «агент молчит».
// В боевом режиме это пульс в памяти. Пока пульса не было и процесс моложе
// порога, решать рано: старая метка в hosts больше не обновляется.
func silenceAt(started, now int64, seen map[string]int64, host string) (int64, bool) {
	if t := seen[host]; t > 0 {
		return t, true
	}
	if started > 0 && now-started <= silentAfterMS {
		return 0, false
	}
	return 1, true
}

func sweepAlertsTx(tx *sql.Tx, now int64, started int64, seen map[string]int64) error {
	pct, _ := strconv.Atoi(settingValue(tx, "disk_pct", "0"))
	if pct < 90 {
		if _, err := closeAlertsWhere(tx, "auto", "место освободилось", now, `rule_id='disk-90'`); err != nil {
			return err
		}
	}
	if pct < 80 {
		if _, err := closeAlertsWhere(tx, "auto", "место освободилось", now, `rule_id='disk-80'`); err != nil {
			return err
		}
	}
	var quarantined int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM agents WHERE trust_state='quarantined'`).Scan(&quarantined); err != nil {
		return err
	}
	if quarantined == 0 {
		if _, err := closeAlertsWhere(tx, "auto", "карантин разобран", now, `rule_id='clone'`); err != nil {
			return err
		}
	}
	type agentRow struct {
		id, host, fwJSON string
		last             int64
		rev              int64
	}
	rows, err := tx.Query(`SELECT a.agent_id, a.host_id, COALESCE(h.last_seen_ms,0), a.policy_rev, COALESCE(fw.v,'')
		FROM agents a LEFT JOIN hosts h ON h.host_id=a.host_id LEFT JOIN settings fw ON fw.k='fw_status:'||a.agent_id
		WHERE a.trust_state='trusted'`)
	if err != nil {
		return err
	}
	var ags []agentRow
	for rows.Next() {
		var r agentRow
		if err = rows.Scan(&r.id, &r.host, &r.last, &r.rev, &r.fwJSON); err != nil {
			rows.Close()
			return err
		}
		ags = append(ags, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, a := range ags {
		live[a.host] = true
		name := hostTitle(tx, a.host)
		stopped := settingValue(tx, "agent_stopped:"+a.host, "") != ""
		if stopped {
			if _, err = closeAlertsWhere(tx, "auto", "агент остановлен", now, `rule_id='silent' AND host_id=?`, a.host); err != nil {
				return err
			}
		}
		last, decide := silenceAt(started, now, seen, a.host)
		if !stopped && decide && last > 0 && now-last > silentAfterMS {
			if err = raiseAlert(tx, a.host, "silent", name+" — агент молчит", now); err != nil {
				return err
			}
		} else if decide && last > 0 {
			if _, err = closeAlertsWhere(tx, "auto", "агент снова на связи", now, `rule_id='silent' AND host_id=?`, a.host); err != nil {
				return err
			}
		}
		fwErr := fwStatusError(a.fwJSON)
		if fwErr != "" {
			if err = raiseAlert(tx, a.host, "policy-fail", name+" — политика не применилась: "+fwErr, now); err != nil {
				return err
			}
		} else if a.fwJSON != "" {
			if _, err = closeAlertsWhere(tx, "auto", "политика применилась", now, `rule_id='policy-fail' AND host_id=?`, a.host); err != nil {
				return err
			}
		}
	}
	// Агента убрали из парка — про его молчание и политику спрашивать некого.
	rows, err = tx.Query(`SELECT DISTINCT host_id FROM alerts WHERE closed_at_ms IS NULL AND rule_id IN ('silent','policy-fail')`)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		if !live[h] {
			gone = append(gone, h)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, h := range gone {
		if _, err = closeAlertsWhere(tx, "auto", "агента больше нет в парке", now, `rule_id IN ('silent','policy-fail') AND host_id=?`, h); err != nil {
			return err
		}
	}
	return nil
}

func fwStatusError(raw string) string {
	if raw == "" {
		return ""
	}
	var st struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &st) != nil {
		return ""
	}
	e := strings.TrimSpace(st.Error)
	if len([]rune(e)) > 160 {
		e = string([]rune(e)[:160]) + "…"
	}
	return e
}

// alertState — цвет строки ленты.
func alertState(closed, seen sql.NullInt64, by string) string {
	switch {
	case !closed.Valid:
		return "red"
	case seen.Valid || by == "adm":
		return "green"
	default:
		return "yellow"
	}
}

func alertCloseText(by, note string) string {
	switch note {
	case "открыл вход":
		note = "снял шторм"
	case "шторм стих, вход открыт":
		note = "шторм стих"
	}
	return note
}

var errAlertClosed = fmt.Errorf("тревога уже закрыта")

func alertOpen(tx *sql.Tx, id string) (rule, host string, err error) {
	var closed sql.NullInt64
	err = tx.QueryRow(`SELECT rule_id, host_id, closed_at_ms FROM alerts WHERE alert_id=?`, id).Scan(&rule, &host, &closed)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("тревога не найдена")
	}
	if err == nil && closed.Valid {
		err = errAlertClosed
	}
	return rule, host, err
}

// endStormNow — «снять шторм»: защита снимается сразу.
func endStormNow(tx *sql.Tx, host string, now int64) error {
	if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, stormKey(host)); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=? AND trust_state='trusted'`, host); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)`,
		idgen.NewV7(), now, "adm", "шторм: снял", host)
	return err
}
