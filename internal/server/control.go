package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
)

type hostControl struct {
	Mode       string `json:"mode"`
	Quarantine bool   `json:"quarantine"`
	PauseFrom  int64  `json:"pause_from"`
	PauseUntil int64  `json:"pause_until"`
}

// «Пока не сниму» — срок, до которого морда не доживёт; число целое и в JS.
const pauseForever int64 = 4_000_000_000_000_000

func (c hostControl) paused(now int64) bool { return c.PauseUntil > now && c.PauseFrom <= now }
func readControl(db policyReader, host string) (hostControl, error) {
	c := hostControl{Mode: "park"}
	var raw string
	err := db.QueryRow("SELECT v FROM settings WHERE k=?", "host_control:"+host).Scan(&raw)
	if err == sql.ErrNoRows {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(raw), &c); err != nil {
		return c, err
	}
	if c.Mode == "" {
		c.Mode = "park"
	}
	return c, nil
}
func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Op, Mode string
		On       bool
		Forever  bool
		FromMS   int64 `json:"from_ms"`
		UntilMS  int64 `json:"until_ms"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "json", 400)
		return
	}
	now := store.NowMS()
	switch in.Op {
	case "mode":
		if in.Mode != "park" && in.Mode != "allow" && in.Mode != "learn" && in.Mode != "block" {
			http.Error(w, "неверный режим", 400)
			return
		}
	case "quarantine":
	case "pause":
		if in.On && in.Forever {
			in.FromMS, in.UntilMS = 0, pauseForever
		}
		if in.On && (in.UntilMS <= now || in.FromMS < 0 || in.FromMS >= in.UntilMS) {
			http.Error(w, "неверный срок паузы", 400)
			return
		}
	default:
		http.Error(w, "неверное действие", 400)
		return
	}
	var c hostControl
	err := s.st.Update(func(tx *sql.Tx) error {
		var host, trust string
		if err := tx.QueryRow("SELECT host_id,trust_state FROM agents WHERE agent_id=?", r.PathValue("id")).Scan(&host, &trust); err != nil {
			return err
		}
		if trust != "trusted" {
			return errAgentState
		}
		var err error
		c, err = readControl(tx, host)
		if err != nil {
			return err
		}
		switch in.Op {
		case "mode":
			c.Mode = in.Mode
		case "quarantine":
			c.Quarantine = in.On
		case "pause":
			c.PauseFrom = 0
			c.PauseUntil = 0
			if in.On {
				c.PauseFrom = in.FromMS
				c.PauseUntil = in.UntilMS
			}
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", "host_control:"+host, string(raw)); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=? AND trust_state='trusted'", host); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail) VALUES(?,?,?,?,?,?)", idgen.NewV7(), now, "adm", "управление сервером: "+in.Op, host, string(raw))
		return err
	})
	if err != nil {
		http.Error(w, fmt.Sprint(err), 400)
		return
	}
	writeJSON(w, c)
}
