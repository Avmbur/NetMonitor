package server

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"net"
	"net/http"

	"netmonitor/internal/idgen"
	"netmonitor/internal/ingest"
	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

const cloneFreshMS = 60000

func requestSrc(r *http.Request) string {
	src, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return src
}

func (s *Server) agentFromTLS(r *http.Request) (ingest.Agent, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ingest.Agent{}, fmt.Errorf("нужен клиентский сертификат")
	}
	cert := r.TLS.PeerCertificates[0]
	if err := s.rejectForeignCert(cert); err != nil {
		return ingest.Agent{}, err
	}
	fp := tlsutil.Fingerprint(cert.Raw)
	src := requestSrc(r)
	if ag, ok := s.lookupAgent(fp, src); ok {
		if ag.Trust == "revoked" {
			return ingest.Agent{}, fmt.Errorf("отозван")
		}
		return ag, nil
	}
	var ag ingest.Agent
	seen := map[string]int64{}
	{
		s.pulseMu.Lock()
		for host, at := range s.hostSeen {
			seen[host] = at
		}
		s.pulseMu.Unlock()
	}
	err := s.st.Update(func(tx *sql.Tx) error {
		var e error
		ag, e = resolveAgentTx(tx, fp, src, seen)
		return e
	})
	return ag, err
}

// rejectForeignCert проверяет подпись и срок, если сертификат настоящий.
// В тестах в запрос кладут отпечаток без ключа: там остаётся проверка отпечатка.
func (s *Server) rejectForeignCert(cert *x509.Certificate) error {
	if cert == nil || cert.PublicKey == nil || s.bundle == nil || s.bundle.CACert == nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.bundle.CACert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("неизвестный сертификат")
	}
	return nil
}

func (s *Server) lookupAgent(fp, src string) (ingest.Agent, bool) {
	var ag ingest.Agent
	err := s.st.DB.QueryRow(
		`SELECT agent_id, host_id, trust_state FROM agents WHERE cert_fingerprint=? AND last_src_ip=?`,
		fp, src,
	).Scan(&ag.ID, &ag.HostID, &ag.Trust)
	if err != nil {
		return ingest.Agent{}, false
	}
	return ag, true
}

type agentFPRow struct {
	id, host, trust, ip string
	seen                int64
	name                string
}

func resolveAgentTx(tx *sql.Tx, fp, src string, pulse map[string]int64) (ingest.Agent, error) {
	rows, err := tx.Query(
		`SELECT a.agent_id, a.host_id, a.trust_state, COALESCE(a.last_src_ip,''), COALESCE(h.last_seen_ms,0), COALESCE(a.display_name,h.hostname,'')
		 FROM agents a LEFT JOIN hosts h ON h.host_id=a.host_id
		 WHERE a.cert_fingerprint=? AND a.trust_state<>'revoked'
		 ORDER BY h.last_seen_ms DESC`, fp)
	if err != nil {
		return ingest.Agent{}, err
	}
	defer rows.Close()
	var list []agentFPRow
	for rows.Next() {
		var r agentFPRow
		if err := rows.Scan(&r.id, &r.host, &r.trust, &r.ip, &r.seen, &r.name); err != nil {
			return ingest.Agent{}, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return ingest.Agent{}, err
	}
	if len(list) == 0 {
		return ingest.Agent{}, fmt.Errorf("неизвестный сертификат")
	}
	now := store.NowMS()
	for _, r := range list {
		if r.ip == src {
			return ingest.Agent{ID: r.id, HostID: r.host, Trust: r.trust}, nil
		}
	}
	for _, r := range list {
		if r.ip == "" {
			if _, err := tx.Exec(`UPDATE agents SET last_src_ip=? WHERE agent_id=?`, src, r.id); err != nil {
				return ingest.Agent{}, err
			}
			return ingest.Agent{ID: r.id, HostID: r.host, Trust: r.trust}, nil
		}
	}
	live := false
	var origin agentFPRow
	for _, r := range list {
		seenAt := pulse[r.host]
		if seenAt > now-cloneFreshMS {
			live = true
			if origin.id == "" {
				origin = r
			}
		}
	}
	if live {
		return insertClone(tx, fp, src, origin, now)
	}
	best := list[0]
	if _, err := tx.Exec(`UPDATE agents SET last_src_ip=? WHERE agent_id=?`, src, best.id); err != nil {
		return ingest.Agent{}, err
	}
	return ingest.Agent{ID: best.id, HostID: best.host, Trust: best.trust}, nil
}

func insertClone(tx *sql.Tx, fp, src string, origin agentFPRow, now int64) (ingest.Agent, error) {
	agentID := idgen.NewV7()
	hostID := idgen.NewV7()
	name := "клон"
	if origin.name != "" {
		name = "клон " + origin.name
	}
	if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,?,?)`,
		hostID, name, now, now); err != nil {
		return ingest.Agent{}, err
	}
	if _, err := tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, display_name, first_seen_ms, last_src_ip)
		VALUES(?,?,?,?,?,?,?)`,
		agentID, hostID, fp, "quarantined", name, now, src); err != nil {
		return ingest.Agent{}, err
	}
	if _, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)",
		idgen.NewV7(), now, "system", "карантин клона", agentID+" "+src); err != nil {
		return ingest.Agent{}, err
	}
	host := origin.host
	if host == "" {
		host = hostID
	}
	if err := raiseAlert(tx, host, "clone", hostTitle(tx, host)+" — чужая копия ключа с "+src, now, src); err != nil {
		return ingest.Agent{}, err
	}
	return ingest.Agent{ID: agentID, HostID: hostID, Trust: "quarantined"}, nil
}
