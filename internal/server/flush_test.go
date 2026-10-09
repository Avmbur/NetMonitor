package server

import (
	"encoding/json"

	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func openFlow(uid string) protocol.FlowPayload {
	now := store.NowMS()
	rp := 443
	return protocol.FlowPayload{
		FlowUID: uid, BootID: "b1", IPVersion: 4, Protocol: "tcp", Direction: "out", Origin: "host",
		OrigSrcIP: "192.168.10.180", OrigDstIP: "1.2.3.4", LocalIP: "192.168.10.180", RemoteIP: "1.2.3.4",
		RemotePort: &rp, FirstSeenMS: now, LastSeenMS: now, State: "ESTABLISHED",
	}
}

func fwEvent(id string, seq int64, hits int) protocol.Event {
	lp := 80
	raw, _ := json.Marshal(protocol.FirewallPayload{
		IPVersion: 4, Protocol: "tcp", Direction: "in",
		LocalIP: "192.168.10.180", RemoteIP: "203.0.113.9",
		LocalPort: &lp, Verdict: "drop", Hits: hits,
	})
	return protocol.Event{EventID: id, Seq: seq, Kind: "firewall", ObservedAtMS: store.NowMS(), Payload: raw}
}

func countTable(t *testing.T, s *Server, table string) int {
	t.Helper()
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(table, err)
	}
	return n
}
