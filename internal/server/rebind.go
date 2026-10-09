package server

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

type rebindOffer struct {
	Status string `json:"status"`
	Pin    string `json:"pin,omitempty"`
	Token  string `json:"token,omitempty"`
}

func (s *Server) handleRebind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	cert := peerCert(r)
	if cert == nil {
		http.Error(w, "нужен клиентский сертификат", http.StatusUnauthorized)
		return
	}
	if err := s.rejectForeignCert(cert); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
		AgentID  string `json:"agent_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
	name := in.Hostname
	if name == "" {
		name = in.AgentID
	}
	fp := tlsutil.Fingerprint(cert.Raw)
	s.noteFormer(requestSrc(r), name, fp)
	token := s.readyRebindToken(fp)
	if token == "" {
		writeJSON(w, rebindOffer{Status: "pending"})
		return
	}
	pin, err := s.serverPin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rebindOffer{Status: "ready", Pin: pin, Token: token})
}

func (s *Server) handleRebindApprove(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if err := s.approveRebind(in.IP); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) approveRebind(ip string) error {
	row, ok := s.formerByIP(ip)
	if !ok || row.FP == "" {
		return fmt.Errorf("агент ещё не представился")
	}
	if s.readyRebindToken(row.FP) != "" {
		return nil
	}
	token := idgen.Token()
	hash := idgen.TokenHash(token)
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO enroll_tokens(token_hash, created_at_ms) VALUES(?,?)`, hash, now); err != nil {
			return err
		}
		return store.PutSetting(tx, "rebind:"+hash, row.FP)
	}); err != nil {
		return err
	}
	s.knockMu.Lock()
	if s.rebindTok == nil {
		s.rebindTok = map[string]string{}
	}
	s.rebindTok[row.FP] = token
	s.knockMu.Unlock()
	return nil
}

func (s *Server) dropUnusedRebind() error {
	return s.st.Update(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT k FROM settings WHERE k LIKE 'rebind:%'`)
		if err != nil {
			return err
		}
		var keys []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, k := range keys {
			hash := strings.TrimPrefix(k, "rebind:")
			if _, err := tx.Exec(`DELETE FROM enroll_tokens WHERE token_hash=? AND used_at_ms IS NULL`, hash); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM settings WHERE k=?`, k); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) readyRebindToken(fp string) string {
	s.knockMu.Lock()
	defer s.knockMu.Unlock()
	return s.rebindTok[fp]
}

func (s *Server) serverPin() (string, error) {
	if s.bundle == nil || s.bundle.ServerTLS == nil || len(s.bundle.ServerTLS.Certificate) == 0 {
		return "", fmt.Errorf("нет сертификата монитора")
	}
	return tlsutil.PublicKeyPin(s.bundle.ServerTLS.Certificate[0])
}

func peerCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
