package server

import (
	"encoding/json"
	"netmonitor/internal/protocol"
	"testing"
)

func TestAgentFieldsFollowAcceptedTelemetry(t *testing.T) {
	s, cert := batchFixture(t)
	raw, _ := json.Marshal(protocol.HealthPayload{Kind: "alive", FWBackend: "nftables", ScopeNote: "scope"})
	if code, _ := sendBatch(t, s, cert, protocol.Event{EventID: "health", Seq: 1, Kind: "health", ObservedAtMS: 1, Payload: raw}); code != 200 {
		t.Fatal(code)
	}
	state := s.uiState("", "settings")
	if state.err != nil || state.Agents[0].FWBackend != "nftables" || state.Agents[0].ScopeNote != "scope" || state.Agents[0].IPv6Seen {
		t.Fatal(state.err, state.Agents)
	}
	// Merely resolving an AAAA is not proof that IPv6 traffic was observed.
	raw, _ = json.Marshal(protocol.DNSPayload{Name: "ipv6.test", IP: "2001:db8::1"})
	if code, _ := sendBatch(t, s, cert, protocol.Event{EventID: "dns", Seq: 2, Kind: "dns", ObservedAtMS: 2, Payload: raw}); code != 200 {
		t.Fatal(code)
	}
	if s.uiState("", "settings").Agents[0].IPv6Seen {
		t.Fatal("DNS set IPv6 seen")
	}
	raw, _ = json.Marshal(protocol.QuestionPayload{RemoteIP: "2001:db8::1", Direction: "out", Protocol: "tcp", RemotePort: 443, DedupKey: "v6"})
	ev := protocol.Event{EventID: "q", Seq: 3, Kind: "question", ObservedAtMS: 3, Payload: raw}
	if code, _ := sendBatch(t, s, cert, ev); code != 200 {
		t.Fatal(code)
	}
	if code, _ := sendBatch(t, s, cert, ev); code != 200 {
		t.Fatal(code)
	}
	if !s.uiState("", "settings").Agents[0].IPv6Seen {
		t.Fatal("observed packet not marked")
	}
	var n int
	s.st.DB.QueryRow("SELECT repeats FROM learn_questions").Scan(&n)
	if n != 1 {
		t.Fatal("duplicate question counted", n)
	}
}
