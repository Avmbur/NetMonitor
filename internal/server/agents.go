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
	// Перепривязка, удаление и сброс берут flushMu раньше записи в базу.
	// Иначе сброс, уже держащий flushMu, ждёт писателя, а этот путь — его.
	// Удаление ещё и снимает отложенные события этого агента, чтобы они
	// не роняли общий сброс после исчезновения строки владельца.
	lockFlush := resume || action == "delete"
	if lockFlush {
		// Wait for accepted batches to finish publishing before clearing their data.
		s.agentStateMu.Lock()
		defer s.agentStateMu.Unlock()
		s.flushMu.Lock()
	}
	var movedFrom, movedTo string
	err := s.st.Update(func(tx *sql.Tx) error {
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
			return s.queueAgentRemoval(tx, id, trust, host, oldName, src)
		case "stop":
			return s.queueAgentStop(tx, id, trust, host, oldName, src)
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
				movedFrom, movedTo = host, old
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
	if err == nil && action == "delete" {
		s.forgetAgentMemory(id)
	}
	if err == nil && movedFrom != "" && movedTo != "" && movedFrom != movedTo {

		s.moveDropHost(movedFrom, movedTo)
		s.moveSSHHost(movedFrom, movedTo)

	}
	if err == nil && s.st != nil {
	}
	if lockFlush {
		s.flushMu.Unlock()
	}
	if err != nil {
		return err
	}
	// Продолжение истории переписывает host_id открытых flows. Память после коммита читает их заново.
	// flushMu уже отпущен: liveReload берёт свою блокировку и очередь снимка.
	if resume {

	}
	// Без диска перечитывать нечего: соединения в памяти переходят на прежний хост.
	if movedFrom != "" && movedTo != "" && movedFrom != movedTo {
		s.moveLiveHost(movedFrom, movedTo)
	}
	return nil
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

func (s *Server) queueAgentRemoval(tx *sql.Tx, id, trust, host, name, src string) error {
	if trust != "trusted" && trust != "pending" && trust != "quarantined" {
		return errAgentState
	}
	if trust == "trusted" {
		var last int64
		s.pulseMu.Lock()
		last = s.hostSeen[host]
		s.pulseMu.Unlock()
		if last < store.NowMS()-60000 {
			return errAgentSilent
		}
	}
	var n int
	var err error
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

func (s *Server) queueAgentStop(tx *sql.Tx, id, trust, host, name, src string) error {
	if trust != "trusted" {
		return errAgentState
	}
	var last int64
	s.pulseMu.Lock()
	last = s.hostSeen[host]
	s.pulseMu.Unlock()
	if last < store.NowMS()-60000 {
		return errAgentSilent
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM commands WHERE agent_id=? AND kind='stop' AND acked_at_ms IS NULL`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := store.NowMS()
	if _, err := tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES(?,?,?,?,?)`, idgen.NewV7(), id, "stop", "{}", now); err != nil {
		return err
	}
	_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,src_ip) VALUES(?,?,?,?,?,?)", idgen.NewV7(), now, "adm", "остановил агента", id+" "+name, src)
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
	if _, err := tx.Exec(`DELETE FROM ingest_events WHERE agent_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE k IN (?,?)`, "fw_status:"+id, "question_floor:"+id); err != nil {
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
		)
		ORDER BY COALESCE(h.last_seen_ms,0) DESC LIMIT 1`, exceptHost, ip, ip).Scan(&id, &name)
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
	for _, q := range []string{
		`UPDATE learn_questions SET host_id=? WHERE host_id=?`,
		`UPDATE blocks SET host_id=? WHERE host_id=?`,
		`UPDATE alerts SET host_id=? WHERE host_id=?`,
	} {
		if _, err := tx.Exec(q, to, from); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO ssh_brute(remote_ip,host_id,attempts,first_at_ms,last_at_ms)
 SELECT remote_ip,?,attempts,first_at_ms,last_at_ms FROM ssh_brute WHERE host_id=?
 ON CONFLICT(remote_ip,host_id) DO UPDATE SET attempts=attempts+excluded.attempts,first_at_ms=MIN(first_at_ms,excluded.first_at_ms),last_at_ms=MAX(last_at_ms,excluded.last_at_ms)`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM ssh_brute WHERE host_id=?", from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_group_host_excl(group_id,host_id) SELECT group_id,? FROM ip_group_host_excl WHERE host_id=?`, to, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ip_group_host_excl WHERE host_id=?`, from); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms)
		SELECT ?,name,ip_bin,ip,first_seen_ms,last_seen_ms FROM dns_seen WHERE host_id=?
		ON CONFLICT(host_id,name,ip_bin) DO UPDATE SET
		  first_seen_ms=MIN(dns_seen.first_seen_ms, excluded.first_seen_ms),
		  last_seen_ms=MAX(dns_seen.last_seen_ms, excluded.last_seen_ms)`, to, from); err != nil {
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
