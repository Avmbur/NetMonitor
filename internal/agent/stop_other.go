//go:build !linux

package agent

import "fmt"

func (a *Agent) scheduleStop(id string) error {
	return fmt.Errorf("остановка агента поддерживается только в Linux (%s)", id)
}
