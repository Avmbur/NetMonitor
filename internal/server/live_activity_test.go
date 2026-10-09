package server

import (
	"encoding/json"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func flowEvent(id string, seq int64, p protocol.FlowPayload) protocol.Event {
	raw, _ := json.Marshal(p)
	return protocol.Event{EventID: id, Seq: seq, Kind: "flow", ObservedAtMS: store.NowMS(), Payload: raw}
}

func uids(flows []uiFlow) []string {
	out := make([]string, 0, len(flows))
	for _, f := range flows {
		out = append(out, f.FlowUID)
	}
	return out
}
