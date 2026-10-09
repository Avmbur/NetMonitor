package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func (s *Server) recordOnceUsed(agentID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			return fmt.Errorf("неверный расход однократного правила")
		}
		seen[id] = true
	}
	return s.st.Update(func(tx *sql.Tx) error {
		var host string
		if err := tx.QueryRow(`SELECT COALESCE(host_id,'') FROM agents WHERE agent_id=?`, agentID).Scan(&host); err != nil {
			return err
		}
		changed := false
		now := store.NowMS()
		for _, id := range ids {
			var raw string
			err := tx.QueryRow("SELECT payload FROM policy_rules WHERE rule_id=?", id).Scan(&raw)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			var rule policy.Rule
			if err = json.Unmarshal([]byte(raw), &rule); err != nil {
				return err
			}
			if !rule.Once || rule.SpentOn(host) {
				continue
			}
			rule.OnceUsedHosts = append(rule.OnceUsedHosts, host)
			rule.Version++
			body, err := json.Marshal(rule)
			if err != nil {
				return err
			}
			if _, err = tx.Exec("UPDATE policy_rules SET version=?,payload=? WHERE rule_id=?", rule.Version, string(body), id); err != nil {
				return err
			}
			if _, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "agent:"+agentID, "правило: однократно израсходовано", id); err != nil {
				return err
			}
			if onceSpentOnTargets(tx, rule) {
				if _, err = tx.Exec("DELETE FROM policy_rules WHERE rule_id=?", id); err != nil {
					return err
				}
			}
			changed = true
		}
		if !changed {
			return nil
		}
		return bumpTrusted(tx)
	})
}

func onceSpentOnTargets(tx *sql.Tx, r policy.Rule) bool {
	if r.OnceUsed {
		return true
	}
	targets := r.Hosts
	if len(targets) == 0 {
		rows, err := tx.Query(`SELECT host_id FROM agents WHERE trust_state='trusted'`)
		if err != nil {
			return false
		}
		defer rows.Close()
		for rows.Next() {
			var h string
			if rows.Scan(&h) == nil && h != "" {
				targets = append(targets, h)
			}
		}
	}
	if len(targets) == 0 {
		return false
	}
	except := map[string]bool{}
	for _, e := range r.Except {
		except[e] = true
	}
	any := false
	for _, h := range targets {
		if except[h] {
			continue
		}
		any = true
		if !r.SpentOn(h) {
			return false
		}
	}
	return any
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	ag, err := s.agentFromTLS(r)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	in := protocol.PollReq{}
	if r.Method == http.MethodPost {
		if err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			http.Error(w, "invalid poll body", 400)
			return
		}
	} else {
		in.Rev, _ = strconv.ParseInt(r.URL.Query().Get("rev"), 10, 64)
		in.Ack = r.URL.Query()["ack"]
	}
	if err = s.recordApply(ag.ID, in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if in.Uninstalled != "" {
		http.Error(w, errOldAgentUninstall, http.StatusConflict)
		return
	}
	if err = s.recordOnceUsed(ag.ID, in.ConsumedOnce); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Reporting never long-polls or consumes the next snapshot.
	if in.Status != nil {
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	changed, err := s.registerStream(ag.ID, in.Instance)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		res, err := s.pollSnapshot(ag.ID, ag.Trust, in.Rev)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if changed || res.PolicyRev != in.Rev || len(res.Commands) > 0 || !res.Authorized {
			s.writePoll(w, ag.ID, res)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			s.writePoll(w, ag.ID, res)
			return
		case <-tick.C:
		}
	}
}
func (s *Server) pollSnapshot(agentID, trust string, clientRev int64) (protocol.PollRes, error) {
	var res protocol.PollRes
	err := s.st.Update(func(tx *sql.Tx) error {
		var err error
		res, err = s.pollSnapshotTx(tx, agentID, trust, clientRev)
		return err
	})
	return res, err
}

// Snapshot, command creation and delivery markers share the writer transaction:
// an edit cannot delete an unseen command between reading and delivering it.
func (s *Server) pollSnapshotTx(tx *sql.Tx, agentID, trust string, clientRev int64) (protocol.PollRes, error) {
	var res protocol.PollRes
	var rev int64
	err := tx.QueryRow(`SELECT policy_rev,trust_state FROM agents WHERE agent_id=?`, agentID).Scan(&rev, &trust)
	if err != nil {
		return res, err
	}
	res.Authorized = trust == "trusted"
	res.PolicyRev = rev
	res.Full = rev != clientRev
	res.NeverBlock, err = policyStrings(tx, "SELECT cidr FROM never_block")
	if err != nil {
		return res, err
	}
	err = tx.QueryRow("SELECT v FROM settings WHERE k='park_mode'").Scan(&res.Mode)
	if err != nil && err != sql.ErrNoRows {
		return res, err
	}
	if res.Mode == "" {
		res.Mode = "learn"
	}
	if trust != "trusted" {
		res.Mode = ""
		return res, nil
	}
	var hostID string
	if err = tx.QueryRow(`SELECT COALESCE(host_id,'') FROM agents WHERE agent_id=?`, agentID).Scan(&hostID); err != nil {
		return res, err
	}
	control, err := readControl(tx, hostID)
	if err != nil {
		return res, err
	}
	if control.Mode != "park" {
		res.Mode = control.Mode
	}
	if control.Quarantine {
		res.Mode = "quarantine"
	}
	now := store.NowMS()
	// Шторм — реакция на атаку, от режима не зависит: новые входы с улицы
	// закрыты при любом режиме. «shield» — прежнее имя «allow+storm», его
	// понимают и агенты, не знающие «+storm».
	res.Mode = stormMode(res.Mode, stormActive(tx, hostID, now))
	res.LocalPauses, err = policyStrings(tx, "SELECT p.block_id FROM block_pause p JOIN blocks b ON b.block_id=p.block_id WHERE p.agent_id=? AND b.state='active' AND (b.expires_at_ms IS NULL OR b.expires_at_ms>?)", agentID, now)
	if err != nil {
		return res, err
	}
	bans, err := readBans(tx,
		`WHERE state='active' AND (expires_at_ms IS NULL OR expires_at_ms>?)
		   AND block_id NOT IN (SELECT block_id FROM block_pause WHERE agent_id=?)`, now, agentID)
	if err != nil {
		return res, err
	}
	for _, b := range bans {
		if !b.covers(hostID) {
			continue
		}
		if err := ensureBanCommand(tx, b, agentID, now); err != nil {
			return res, err
		}
		res.Blocks = append(res.Blocks, protocol.BlockView{
			BlockID: b.ID, RemoteIP: b.RemoteIP, Protocol: b.Protocol, Port: b.Port,
			LocalPort: b.LocalPort, Direction: b.Direction, ExpiresAt: b.ExpiresAt, State: b.State,
		})
	}

	res.Model = 1
	res.Rules, err = hostRules(tx, hostID)
	if err != nil {
		return res, err
	}
	res.Groups, err = hostGroups(tx, hostID)
	if err != nil {
		return res, err
	}
	res.LAN = splitCIDRs(settingValue(tx, "lan", ""))
	res.Own, err = parkOwn(tx, hostID)
	if err != nil {
		return res, err
	}
	res.ObserveDocker = settingValue(tx, "observe_docker", "") == "1"
	res.ScanPorts = settingInt(tx, "scan_ports", 5)
	res.ScanWindowMS = int64(settingInt(tx, "scan_window_s", 60)) * 1000
	cmds, err := tx.Query(
		`SELECT command_id, kind, payload, COALESCE(block_id,'') FROM commands WHERE agent_id=? AND acked_at_ms IS NULL ORDER BY created_at_ms LIMIT 50`,
		agentID)
	if err != nil {
		return res, err
	}
	defer cmds.Close()
	for cmds.Next() {
		var c protocol.Command
		if err := cmds.Scan(&c.ID, &c.Kind, &c.Payload, &c.BlockID); err != nil {
			return res, err
		}
		res.Commands = append(res.Commands, c)
	}
	if err := cmds.Err(); err != nil {
		return res, err
	}
	cmds.Close()
	for _, c := range res.Commands {
		if _, err := tx.Exec(`UPDATE commands SET delivered_at_ms=COALESCE(delivered_at_ms,?),delivered_rev=COALESCE(delivered_rev,?) WHERE command_id=? AND agent_id=?`, now, rev, c.ID, agentID); err != nil {
			return res, err
		}
	}
	return res, nil
}

func splitCIDRs(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func settingInt(db policyReader, k string, fallback int) int {
	v := settingValue(db, k, "")
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parkOwn(db policyReader, self string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			s = fmt.Sprintf("%s/%d", a, a.BitLen())
		}
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	rows, err := db.Query(`SELECT COALESCE(last_src_ip,'') FROM agents WHERE trust_state='trusted' AND COALESCE(host_id,'')<>?`, self)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			add(ip)
		}
	}
	rows.Close()
	inv, err := db.Query(`SELECT k,v FROM settings WHERE k LIKE 'inventory:%'`)
	if err != nil {
		return out, err
	}
	defer inv.Close()
	for inv.Next() {
		var k, v string
		if inv.Scan(&k, &v) != nil {
			continue
		}
		if strings.TrimPrefix(k, "inventory:") == self {
			continue
		}
		var h protocol.HealthPayload
		if json.Unmarshal([]byte(v), &h) != nil {
			continue
		}
		for _, a := range h.Addresses {
			add(a)
		}
	}
	return out, inv.Err()
}
