//go:build !linux

package agent

import "fmt"

func (a *Agent) scheduleUpdate(string, string) error {
	return fmt.Errorf("обновление агента доступно на linux")
}

func updateUnitActive(string) (bool, error) { return false, fmt.Errorf("update requires Linux") }
