package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
)

func (s *Server) handleRemoveMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Agents bool `json:"agents"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil && err != io.EOF {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	wait, err := s.requestMonitorRemoval(in.Agents, requestSrc(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ready := removePathActive()
	detail := ""
	if !ready {
		detail = "запрос записан, но служба удаления не запущена. эта установка его не выполнит. нужен комплект, в котором nm-remove.path запускается"
	}
	writeJSON(w, map[string]any{"ok": true, "wait": wait, "ready": ready, "detail": detail})
}

func removePathActive() bool {
	out, err := exec.Command("systemctl", "is-active", "nm-remove.path").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

func (s *Server) requestMonitorRemoval(agents bool, src string) (int, error) {
	wait := 0
	if agents {
		wait = 45
		if err := s.st.Update(func(tx *sql.Tx) error {
			rows, err := tx.Query(`SELECT agent_id, COALESCE(display_name,'') FROM agents WHERE trust_state<>'revoked'`)
			if err != nil {
				return err
			}
			defer rows.Close()
			type item struct{ id, name string }
			var list []item
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.id, &it.name); err != nil {
					return err
				}
				list = append(list, it)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows.Close()
			now := store.NowMS()
			for _, it := range list {
				var n int
				if err := tx.QueryRow(`SELECT COUNT(*) FROM commands WHERE agent_id=? AND kind='uninstall' AND acked_at_ms IS NULL`, it.id).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					continue
				}
				if _, err := tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES(?,?,?,?,?)`, idgen.NewV7(), it.id, "uninstall", "{}", now); err != nil {
					return err
				}
				if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,src_ip) VALUES(?,?,?,?,?,?)", idgen.NewV7(), now, "adm", "запросил снятие агента", it.id+" "+it.name, src); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	dir := s.cfg.DataDir
	if dir == "" && s.st != nil {
		dir = filepath.Dir(s.st.Path())
	}
	if dir == "" {
		return 0, fmt.Errorf("нет каталога монитора")
	}
	body := fmt.Sprintf("agents=%d\nwait=%d\n", boolBit(agents), wait)
	path := filepath.Join(dir, "remove.request")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o640); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	return wait, nil
}

func boolBit(v bool) int {
	if v {
		return 1
	}
	return 0
}
