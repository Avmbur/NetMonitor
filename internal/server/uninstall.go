package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

// Completion receipts outlive the agent row so a lost HTTP response is retryable.
// They authorize only this command's completion, never polls or new commands.
func (s *Server) handleUninstallResult(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	var in protocol.UninstallResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid removal result", http.StatusBadRequest)
		return
	}
	fp := tlsutil.Fingerprint(r.TLS.PeerCertificates[0].Raw)
	if err := s.recordUninstall(fp, in); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) recordUninstall(fp string, in protocol.UninstallResult) error {
	if in.CommandID == "" || len(in.CommandID) > 128 || len(in.Error) > 4096 {
		return fmt.Errorf("invalid removal result")
	}
	if in.Phase != "prepare" && in.Phase != "failed" && in.Phase != "complete" {
		return fmt.Errorf("invalid removal phase")
	}
	if in.Phase != "failed" && in.Error != "" || in.Phase == "failed" && in.Error == "" {
		return fmt.Errorf("invalid removal error")
	}
	return s.st.Update(func(tx *sql.Tx) error {
		key := "uninstall_done:" + in.CommandID
		var receipt string
		err := tx.QueryRow("SELECT v FROM settings WHERE k=?", key).Scan(&receipt)
		if err == nil {
			if receipt == fp && in.Phase == "complete" {
				return nil
			}
			return fmt.Errorf("removal already completed")
		}
		if err != sql.ErrNoRows {
			return err
		}
		var agentID, trust, host, name, kind, owner, result string
		var delivered, acked sql.NullInt64
		err = tx.QueryRow(`SELECT a.agent_id,a.trust_state,a.host_id,COALESCE(a.display_name,''),c.kind,a.cert_fingerprint,c.delivered_at_ms,c.acked_at_ms,COALESCE(c.result,'')
   FROM commands c JOIN agents a ON a.agent_id=c.agent_id WHERE c.command_id=?`, in.CommandID).
			Scan(&agentID, &trust, &host, &name, &kind, &owner, &delivered, &acked, &result)
		if err != nil {
			return err
		}
		if owner != fp || trust != "trusted" || kind != "uninstall" || !delivered.Valid || acked.Valid {
			return fmt.Errorf("removal was not delivered to this trusted agent")
		}
		switch in.Phase {
		case "prepare":
			_, err = tx.Exec("UPDATE commands SET result='removing',error=NULL WHERE command_id=?", in.CommandID)
			return err
		case "failed":
			_, err = tx.Exec("UPDATE commands SET result='remove_error',error=? WHERE command_id=?", in.Error, in.CommandID)
			return err
		case "complete":
			if result != "removing" && result != "remove_error" {
				return fmt.Errorf("removal was not prepared")
			}
			if err := store.PutSetting(tx, key, fp); err != nil {
				return err
			}
			return deleteAgentRow(tx, agentID, trust, host, name, "", "снял агента с сервера")
		}
		return nil
	})
}
