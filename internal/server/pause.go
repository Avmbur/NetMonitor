package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"sort"
	"strings"
)

func (s *Server) handleLocalUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	ag, err := s.agentFromTLS(r)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	var req protocol.LocalUnblock
	if err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.RequestID == "" || len(req.RequestID) > 128 || len(req.BlockIDs) == 0 || len(req.BlockIDs) > 1000 {
		http.Error(w, "request_id and block_ids required", 400)
		return
	}
	if err = s.pauseBlocks(ag.ID, req); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"status": "paused_local"})
}
func (s *Server) pauseBlocks(agentID string, req protocol.LocalUnblock) error {
	// Консольный unblock и старый агент без причины бан не отключают.
	// 200, чтобы агент снял локальную паузу на следующем опросе и бан вернулся.
	if req.Reason != "rollback" {
		return nil
	}
	sort.Strings(req.BlockIDs)
	raw, err := json.Marshal(req.BlockIDs)
	if err != nil {
		return err
	}
	key := "local_pause:" + agentID + ":" + req.RequestID
	return s.st.Update(func(tx *sql.Tx) error {
		var prior string
		err := tx.QueryRow("SELECT v FROM settings WHERE k=?", key).Scan(&prior)
		if err == nil {
			if prior != string(raw) {
				return fmt.Errorf("pause request reused with different blocks")
			}
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		var host, trust string
		if err = tx.QueryRow("SELECT COALESCE(host_id,''),trust_state FROM agents WHERE agent_id=?", agentID).Scan(&host, &trust); err != nil {
			return err
		}
		if trust != "trusted" {
			return fmt.Errorf("agent not trusted")
		}
		var changed int64
		var ips []string
		seenIP := map[string]bool{}
		for _, id := range req.BlockIDs {
			// A server may only pause a ban that actually reaches it.
			b, e := readBan(tx, id)
			if e == sql.ErrNoRows {
				continue
			}
			if e != nil {
				return e
			}
			if !b.covers(host) {
				continue
			}
			result, e := tx.Exec("INSERT OR IGNORE INTO block_pause(agent_id,block_id,paused_at_ms) VALUES(?,?,?)", agentID, id, store.NowMS())
			if e != nil {
				return e
			}
			n, e := result.RowsAffected()
			if e != nil {
				return e
			}
			changed += n
			if b.RemoteIP != "" && !seenIP[b.RemoteIP] {
				seenIP[b.RemoteIP] = true
				ips = append(ips, b.RemoteIP)
			}
		}
		if changed > 0 {
			if _, err = tx.Exec("UPDATE agents SET policy_rev=policy_rev+1 WHERE agent_id=?", agentID); err != nil {
				return err
			}
			if _, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), store.NowMS(), agentID, "бан снят на сервере", string(raw)); err != nil {
				return err
			}
			name := hostTitle(tx, host)
			summary := "бан снят руками"
			if name != "" && name != "монитор" {
				summary += " на " + name
			}
			if len(ips) == 1 {
				summary = withAlertIP(ips[0], summary)
			} else if len(ips) > 1 {
				summary = strings.Join(ips, ", ") + " — " + summary
			}
			if err = raiseAlert(tx, host, "paused_local", summary, store.NowMS(), ips...); err != nil {
				return err
			}
		}
		return store.PutSetting(tx, key, string(raw))
	})
}

func restorePausedFromAlert(tx *sql.Tx, alertID string, now int64) error {
	var rule, host, summary string
	var closed sql.NullInt64
	err := tx.QueryRow(`SELECT rule_id, host_id, summary, closed_at_ms FROM alerts WHERE alert_id=?`, alertID).Scan(&rule, &host, &summary, &closed)
	if err == sql.ErrNoRows {
		return fmt.Errorf("тревога не найдена")
	}
	if err != nil {
		return err
	}
	if rule != "paused_local" {
		return fmt.Errorf("вернуть бан можно только для снятого на сервере")
	}
	if closed.Valid {
		return fmt.Errorf("тревога уже закрыта")
	}
	var ips []string
	rows, err := tx.Query(`SELECT ref_id FROM alert_refs WHERE alert_id=? AND ref_kind='ip'`, alertID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip string
		if err = rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		if ip := lastIPv4(summary); ip != "" {
			ips = []string{ip}
		}
	}
	var agentID string
	err = tx.QueryRow(`SELECT agent_id FROM agents WHERE host_id=? AND trust_state='trusted' LIMIT 1`, host).Scan(&agentID)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if agentID != "" {
		if len(ips) == 0 {
			if _, err = tx.Exec(`DELETE FROM block_pause WHERE agent_id=?`, agentID); err != nil {
				return err
			}
		} else {
			args := []any{agentID}
			ph := make([]string, len(ips))
			for i, ip := range ips {
				ph[i] = "?"
				args = append(args, ip)
			}
			q := `DELETE FROM block_pause WHERE agent_id=? AND block_id IN (SELECT block_id FROM blocks WHERE remote_ip IN (` + strings.Join(ph, ",") + `))`
			if _, err = tx.Exec(q, args...); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`UPDATE agents SET policy_rev=policy_rev+1 WHERE agent_id=?`, agentID); err != nil {
			return err
		}
	}
	ok, err := closeAlert(tx, alertID, "adm", "вернул бан", now)
	if err != nil {
		return err
	}
	if !ok {
		return errAlertClosed
	}
	obj := host
	if len(ips) > 0 {
		obj = strings.Join(ips, ", ")
	}
	_, err = tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)`,
		idgen.NewV7(), now, "adm", "вернул бан", obj)
	return err
}
