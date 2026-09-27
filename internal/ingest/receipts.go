package ingest

import (
	"database/sql"
	"fmt"
)

// ConfirmQueue records the first sequence still present in any sender lane.
// A smaller value from a concurrent, older batch cannot move it backwards.
func ConfirmQueue(tx *sql.Tx, agentID string, pendingFrom int64) error {
	if pendingFrom < 1 {
		return fmt.Errorf("invalid pending_from")
	}
	if _, err := tx.Exec("UPDATE agents SET pending_from=MAX(pending_from,?) WHERE agent_id=?", pendingFrom, agentID); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM ingest_events WHERE agent_id=? AND seq<(SELECT pending_from FROM agents WHERE agent_id=?)`, agentID, agentID)
	return err
}
