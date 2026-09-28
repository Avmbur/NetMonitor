package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errAgentMissing = errors.New("агент не найден")
var errAgentState = errors.New("действие недоступно в текущем состоянии агента")
var errAgentSilent = errors.New("агент молчит")
var errNoResume = errors.New("нет похожего сервера")

func (s *Server) changeAgent(id, action, name, src string) error {
	return s.applyAgentChange(id, action, name, src, false)
}

func (s *Server) applyAgentChange(id, action, name, src string, resume bool) error {
	return s.st.Update(func(tx *sql.Tx) error {
		var trust, host, oldName, lastIP string
		err := tx.QueryRow("SELECT trust_state,host_id,COALESCE(display_name,''),COALESCE(last_src_ip,'') FROM agents WHERE agent_id=?", id).Scan(&trust, &host, &oldName, &lastIP)
		if err == sql.ErrNoRows {
			return errAgentMissing
		}
		if err != nil {
			return err
		}
		next := ""
		label := ""
		switch action {
		case "trust":
			if trust != "pending" {
				return errAgentState
			}
			next = "trusted"
			label = "подтвердил агента"
			name = strings.TrimSpace(name)
			if name == "" {
				name = oldName
			}
			if name == "" || utf8.RuneCountInString(name) > 128 || strings.ContainsFunc(name, unicode.IsControl) {
				return fmt.Errorf("имя: 1–128 символов без управляющих знаков")
			}
		case "reject":
			if trust != "pending" {
				return errAgentState
			}
			next = "revoked"
			label = "отклонил агента"
		case "revoke":
			if trust != "trusted" && trust != "quarantined" {
				return errAgentState
			}
			next = "revoked"
			label = "отозвал сертификат"
		case "delete":
			return deleteAgentRow(tx, id, trust, host, oldName, src, "")
		case "remove":
			return queueAgentRemoval(tx, id, trust, host, oldName, src)
		default:
			return errAgentState
		}
		now := store.NowMS()
		if next == "revoked" {
			if _, err = tx.Exec(`UPDATE alerts SET closed_at_ms=? WHERE rule_id='clone' AND closed_at_ms IS NULL
				AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.trust_state='quarantined' AND a.agent_id!=?)`, now, id); err != nil {
				return err
			}
		}
		if action == "trust" {
			if resume {
				old, err := findOrphanHost(tx, oldName, lastIP, host)
				if err != nil {
					return err
				}
				if old == "" {
					return errNoResume
				}
				if err := rebindAgentHost(tx, id, host, old); err != nil {
					return err
				}
				label = "подтвердил агента, продолжил историю"
			}
			if _, err = tx.Exec("UPDATE agents SET trust_state=?,display_name=?,approved_at_ms=?,approved_by='adm',policy_rev=policy_rev+1 WHERE agent_id=?", next, name, now, id); err != nil {
				return err
			}
		} else {
			if _, err = tx.Exec("UPDATE agents SET trust_state=?,policy_rev=policy_rev+1 WHERE agent_id=?", next, id); err != nil {
				return err
			}
		}
		_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,src_ip) VALUES(?,?,?,?,?,?)", idgen.NewV7(), now, "adm", label, id+" "+name, src)
		return err
	})
}
func (s *Server) handleAgentAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "control" {
		s.handleControl(w, r)
		return
	}
	if action == "" {
		action = "trust"
	}
	var in struct {
		Name   string `json:"name"`
		Resume bool   `json:"resume"`
	}
	if action == "trust" {
		err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in)
		if err != nil && err != io.EOF {
			http.Error(w, "неверное имя", 400)
			return
		}
	}
	err := s.applyAgentChange(r.PathValue("id"), action, in.Name, r.RemoteAddr, in.Resume)
	if err != nil {
		code := 500
		if errors.Is(err, errAgentMissing) {
			code = 404
		}
		if errors.Is(err, errAgentState) || errors.Is(err, errAgentSilent) || errors.Is(err, errNoResume) {
			code = 409
		}
		if strings.HasPrefix(err.Error(), "имя:") {
			code = 400
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func queueAgentRemoval(tx *sql.Tx, id, trust, host, name, src string) error {
	if trust != "trusted" {
		return errAgentState
	}
	var last int64
	err := tx.QueryRow(`SELECT COALESCE(last_seen_ms,0) FROM hosts WHERE host_id=?`, host).Scan(&last)
	if err == sql.ErrNoRows {
		last = 0
		err = nil
	}
	if err != nil {
		return err
	}
	if last < store.NowMS()-60000 {
		return errAgentSilent
	}
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM commands WHERE agent_id=? AND kind='uninstall' AND acked_at_ms IS NULL`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := store.NowMS()
	if _, err = tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES(?,?,?,?,?)`, idgen.NewV7(), id, "uninstall", "{}", now); err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,src_ip) VALUES(?,?,?,?,?,?)", idgen.NewV7(), now, "adm", "запросил снятие агента", id+" "+name, src)
	return err
}

func deleteAgentRow(tx *sql.Tx, id, trust, host, name, src, action string) error {
	if action == "" {
		action = "забыл агента"
	}
	now := store.NowMS()
	if _, err := tx.Exec(`UPDATE alerts SET closed_at_ms=? WHERE rule_id='clone' AND closed_at_ms IS NULL
		AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.trust_state='quarantined' AND a.agent_id!=?)`, now, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM commands WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM collector_health WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ingest_events WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, "fw_status:"+id); err != nil {
		return err
	}
	var lastIP string
	_ = tx.QueryRow(`SELECT COALESCE(last_src_ip,'') FROM agents WHERE agent_id=?`, id).Scan(&lastIP)
	if ip := strings.TrimSpace(lastIP); ip != "" {
		if err := store.PutSetting(tx, "last_ip:"+host, ip); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM agents WHERE agent_id=?`, id); err != nil {
		return err
	}
	_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,src_ip) VALUES(?,?,?,?,?,?)",
		idgen.NewV7(), now, "adm", action, id+" "+name, src)
	return err
}

func findOrphanHost(tx *sql.Tx, hostname, ip, exceptHost string) (string, error) {
	id, _, err := scanOrphanHost(tx, hostname, ip, exceptHost)
	return id, err
}

func peekOrphanHost(db *sql.DB, hostname, ip, exceptHost string) (id, name string) {
	id, name, _ = scanOrphanHost(db, hostname, ip, exceptHost)
	return id, name
}

type orphanScanner interface {
	QueryRow(query string, args ...any) *sql.Row
}

func scanOrphanHost(q orphanScanner, hostname, ip, exceptHost string) (id, name string, err error) {
	hostname = strings.TrimSpace(hostname)
	ip = strings.TrimSpace(ip)
	orphan := `h.host_id!=? AND NOT EXISTS (
		SELECT 1 FROM agents a WHERE a.host_id=h.host_id AND a.trust_state IN ('pending','trusted','quarantined'))`
	if hostname != "" {
		err = q.QueryRow(`SELECT h.host_id, COALESCE(NULLIF(trim(h.hostname),''), ?) FROM hosts h
			WHERE `+orphan+` AND lower(trim(COALESCE(h.hostname,'')))=lower(?)
			ORDER BY COALESCE(h.last_seen_ms,0) DESC LIMIT 1`, exceptHost, hostname, hostname).Scan(&id, &name)
		if err == nil {
			return id, name, nil
		}
		if err != sql.ErrNoRows {
			return "", "", err
		}
	}
	if ip == "" {
		return "", "", nil
	}
	err = q.QueryRow(`SELECT h.host_id, COALESCE(NULLIF(trim(h.hostname),''), ?) FROM hosts h
		WHERE `+orphan+` AND (
			EXISTS (SELECT 1 FROM settings s WHERE s.k='last_ip:'||h.host_id AND s.v=?)
			OR EXISTS (SELECT 1 FROM flows f WHERE f.host_id=h.host_id AND f.local_ip=?)
		)
		ORDER BY COALESCE(h.last_seen_ms,0) DESC LIMIT 1`, exceptHost, ip, ip, ip).Scan(&id, &name)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return id, name, err
}

func rebindAgentHost(tx *sql.Tx, agentID, from, to string) error {
	if from == "" || to == "" || from == to {
		return nil
	}
	if _, err := tx.Exec(`UPDATE agents SET host_id=? WHERE agent_id=?`, to, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE flows SET agent_id=? WHERE host_id=?`, agentID, from); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE flows SET host_id=? WHERE host_id=?`,
		`UPDATE firewall_events SET host_id=? WHERE host_id=?`,
		`UPDATE learn_questions SET host_id=? WHERE host_id=?`,
		`UPDATE ssh_failures SET host_id=? WHERE host_id=?`,
		`UPDATE collector_health SET host_id=? WHERE host_id=?`,
		`UPDATE blocks SET host_id=? WHERE host_id=?`,
		`UPDATE alerts SET host_id=? WHERE host_id=?`,
	} {
		if _, err := tx.Exec(q, to, from); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE flows SET agent_id=? WHERE host_id=?`, agentID, to); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE flow_samples SET agent_id=? WHERE flow_uid IN (SELECT flow_uid FROM flows WHERE host_id=?)`, agentID, to); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE collector_health SET agent_id=? WHERE host_id=?`, agentID, to); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO traffic_1m(host_id,bucket_start_ms,direction,remote_scope,bytes_out,bytes_in,samples)
		SELECT ?,bucket_start_ms,direction,remote_scope,bytes_out,bytes_in,samples FROM traffic_1m WHERE host_id=?
		ON CONFLICT(host_id,bucket_start_ms,direction,remote_scope) DO UPDATE SET
		  bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in, samples=samples+excluded.samples`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM traffic_1m WHERE host_id=?`, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO traffic_1h(host_id,bucket_start_ms,direction,remote_scope,bytes_out,bytes_in,flows,dirty)
		SELECT ?,bucket_start_ms,direction,remote_scope,bytes_out,bytes_in,flows,dirty FROM traffic_1h WHERE host_id=?
		ON CONFLICT(host_id,bucket_start_ms,direction,remote_scope) DO UPDATE SET
		  bytes_out=bytes_out+excluded.bytes_out, bytes_in=bytes_in+excluded.bytes_in, flows=flows+excluded.flows`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM traffic_1h WHERE host_id=?`, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_group_host_excl(group_id,host_id) SELECT group_id,? FROM ip_group_host_excl WHERE host_id=?`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ip_group_host_excl WHERE host_id=?`, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO remote_seen(host_id,remote_ip_bin,remote_ip,first_seen_ms,last_seen_ms,flows)
		SELECT ?,remote_ip_bin,remote_ip,first_seen_ms,last_seen_ms,flows FROM remote_seen WHERE host_id=?
		ON CONFLICT(host_id,remote_ip_bin) DO UPDATE SET last_seen_ms=excluded.last_seen_ms, flows=remote_seen.flows+excluded.flows`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM remote_seen WHERE host_id=?`, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms)
		SELECT ?,name,ip_bin,ip,first_seen_ms,last_seen_ms FROM dns_seen WHERE host_id=?
		ON CONFLICT(host_id,name,ip_bin) DO UPDATE SET last_seen_ms=excluded.last_seen_ms`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dns_seen WHERE host_id=?`, from); err != nil {
		return err
	}
	for _, pair := range [][2]string{{"inventory:", from}, {"host_control:", from}, {"last_ip:", from}} {
		fromK, toK := pair[0]+from, pair[0]+to
		var exists int
		_ = tx.QueryRow(`SELECT COUNT(*) FROM settings WHERE k=?`, toK).Scan(&exists)
		if exists == 0 {
			if _, err := tx.Exec(`UPDATE settings SET k=? WHERE k=?`, toK, fromK); err != nil {
				return err
			}
		} else if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, fromK); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`DELETE FROM hosts WHERE host_id=?`, from)
	return err
}
