package server

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

// Status and command ACK are one DB transaction. A legacy receipt-only ACK is
// insufficient evidence that the kernel accepted a policy.
func (s *Server) recordApply(agentID string, in protocol.PollReq) error {
	st := in.Status
	if st == nil {
		if len(in.Ack) > 0 {
			return fmt.Errorf("ACK requires application result")
		}
		return nil
	}
	if st.Backend != "nftables" && st.Backend != "iptables" && st.Backend != "unknown" {
		return fmt.Errorf("unknown firewall backend")
	}
	if st.DesiredRev < 0 || st.AppliedRev != nil && (*st.AppliedRev < 0 || *st.AppliedRev > st.DesiredRev) {
		return fmt.Errorf("invalid applied revision")
	}
	success := st.Error == "" && st.AppliedRev != nil && *st.AppliedRev == st.DesiredRev && (st.Backend == "nftables" || st.Backend == "iptables")
	attempted := map[string]bool{}
	for _, id := range st.CommandIDs {
		attempted[id] = true
	}
	for _, id := range in.Ack {
		if !success || !attempted[id] {
			return fmt.Errorf("ACK without successful application")
		}
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.st.Update(func(tx *sql.Tx) error {
		var desired int64
		if err := tx.QueryRow(`SELECT policy_rev FROM agents WHERE agent_id=?`, agentID).Scan(&desired); err != nil {
			return err
		}
		if st.DesiredRev > desired {
			return fmt.Errorf("unissued policy revision")
		}
		if _, err := tx.Exec(`UPDATE agents SET fw_backend=? WHERE agent_id=?`, st.Backend, agentID); err != nil {
			return err
		}
		if err := store.PutSetting(tx, "fw_status:"+agentID, string(raw)); err != nil {
			return err
		}
		for _, id := range st.CommandIDs {
			var delivered, deliveredRev sql.NullInt64
			if err := tx.QueryRow(`SELECT delivered_at_ms,delivered_rev FROM commands WHERE command_id=? AND agent_id=?`, id, agentID).Scan(&delivered, &deliveredRev); err != nil {
				return err
			}
			if !delivered.Valid || !deliveredRev.Valid {
				return fmt.Errorf("command was not delivered")
			}
			if st.DesiredRev < deliveredRev.Int64 {
				return fmt.Errorf("command belongs to a later policy revision")
			}
			if st.Error != "" {
				if _, err := tx.Exec(`UPDATE commands SET result='error',error=? WHERE command_id=? AND agent_id=? AND acked_at_ms IS NULL`, st.Error, id, agentID); err != nil {
					return err
				}
			}
		}
		for _, id := range in.Ack {
			if _, err := tx.Exec(`UPDATE commands SET acked_at_ms=COALESCE(acked_at_ms,?),result='applied',error=NULL WHERE command_id=? AND agent_id=?`, store.NowMS(), id, agentID); err != nil {
				return err
			}
		}
		return nil
	})
}
