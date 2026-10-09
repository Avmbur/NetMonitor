package ingest

import (
	"database/sql"
	"encoding/json"
	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
)

type Agent struct{ DeliveryLane, ID, HostID, Trust string }
type Result struct {
	Ack   []string
	Err   string
	Fatal error
}

func RecordIPv6(tx *sql.Tx, ag Agent, ev protocol.Event) error {
	var p struct {
		IPVersion int                   `json:"ip_version"`
		RemoteIP  string                `json:"remote_ip"`
		Flow      *protocol.FlowPayload `json:"flow"`
	}
	switch ev.Kind {
	case "flow", "sample", "firewall", "question":
	default:
		return nil
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	seen := p.IPVersion == 6
	if p.Flow != nil && p.Flow.IPVersion == 6 {
		seen = true
	}
	if a, e := netipx.Parse(p.RemoteIP); e == nil && a.Unmap().Is6() {
		seen = true
	}
	if seen {
		_, err := tx.Exec("UPDATE agents SET ipv6_seen=1 WHERE agent_id=? AND COALESCE(ipv6_seen,0)=0", ag.ID)
		return err
	}
	return nil
}
