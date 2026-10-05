package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"netmonitor/internal/policy"
	"netmonitor/internal/store"
)

func (s *Server) expireBlocks(now int64) error {
	return s.st.Update(func(tx *sql.Tx) error {
		rows, err := tx.Query("SELECT "+banColumns+" FROM blocks WHERE state='active' AND expires_at_ms IS NOT NULL AND expires_at_ms<=?", now)
		if err != nil {
			return err
		}
		var due []banRecord
		for rows.Next() {
			b, err := scanBan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			due = append(due, b)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		n := 0
		for _, b := range due {
			res, err := tx.Exec("UPDATE blocks SET state='expired' WHERE block_id=? AND state='active'", b.ID)
			if err != nil {
				return err
			}
			changed, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if changed != 1 {
				continue
			}
			b.State = "expired"
			// Одна строка на бан: повторный проход уже не видит state='active'.
			if err = auditBan(tx, "auto", "бан истёк", b.banSpec, now); err != nil {
				return err
			}
			n++
		}
		if n > 0 {
			return bumpTrusted(tx)
		}
		return nil
	})
}

func (s *Server) expireRules(now int64) error {
	return s.st.Update(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT rule_id, payload FROM policy_rules`)
		if err != nil {
			return err
		}
		var drop []string
		for rows.Next() {
			var id, raw string
			if rows.Scan(&id, &raw) != nil {
				continue
			}
			var r policy.Rule
			if json.Unmarshal([]byte(raw), &r) != nil {
				continue
			}
			if r.UntilMS > 0 && r.UntilMS <= now {
				drop = append(drop, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(drop) == 0 {
			return nil
		}
		for _, id := range drop {
			if _, err := tx.Exec(`DELETE FROM policy_rules WHERE rule_id=?`, id); err != nil {
				return err
			}
		}
		return bumpTrusted(tx)
	})
}

func (s *Server) expiryLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var swept int64
	for {
		now := store.NowMS()
		// Тревоги сверяем реже: молчание агента меряется минутами.
		if now-swept >= 10_000 {
			swept = now
			if err := s.sweepAlerts(now); err != nil {
				log.Printf("sweep alerts: %v", err)
			}
		}
		if err := s.expireBlocks(now); err != nil {
			log.Printf("expire blocks: %v", err)
		}
		if err := s.expireRules(now); err != nil {
			log.Printf("expire rules: %v", err)
		}
		if err := s.expireStorms(now); err != nil {
			log.Printf("expire storms: %v", err)
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}
