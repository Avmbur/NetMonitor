//go:build linux

package agent

import "testing"

func TestScheduleUpdateChecksRunningFirst(t *testing.T) {
	a := &Agent{updating: "c1"}
	// Even an invalid payload must not inspect markers or report a failure while running.
	if err := a.scheduleUpdate("c1", "invalid"); err != nil {
		t.Fatal(err)
	}
}
