//go:build linux

package agent

import (
	"log"
	"os/exec"
	"time"
)

// scheduleStop asks systemd to stop this service after the poll acknowledgement
// has been sent. The program, its database and the firewall table stay.
func (a *Agent) scheduleStop(id string) error {
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := exec.Command("systemctl", "stop", "nmagent.service").Run(); err != nil {
			log.Printf("stop %s: %v", id, err)
		}
	}()
	return nil
}
