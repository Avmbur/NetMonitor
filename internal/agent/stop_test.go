package agent

import (
	"errors"
	"slices"
	"testing"

	"netmonitor/internal/protocol"
)

// An unacknowledged stop stays queued on the monitor. Stopping anyway would
// make the agent stop again after every manual start.
func TestStopOnlyAfterAcknowledgement(t *testing.T) {
	for _, failFW := range []bool{true, false} {
		a, f, reports, _ := agentFixture(t)
		if failFW {
			f.err = errors.New("broken firewall")
		}
		stopped := 0
		a.startStop = func(id string) error {
			if id != "halt" {
				t.Fatal(id)
			}
			stopped++
			return nil
		}
		pr := policy(2)
		pr.Commands = []protocol.Command{{ID: "halt", Kind: "stop"}}
		_ = a.applyPoll(pr)
		acked := false
		for _, r := range *reports {
			acked = acked || slices.Contains(r.Ack, "halt")
		}
		if acked != !failFW || stopped != map[bool]int{true: 0, false: 1}[failFW] {
			t.Fatalf("firewall error=%v: acked=%v stopped=%d", failFW, acked, stopped)
		}
	}
}
