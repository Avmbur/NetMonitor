//go:build !linux

package agent

import "fmt"

func (a *Agent) scheduleUninstall(string) error { return fmt.Errorf("removal requires Linux") }
func RunUninstallWorker() error                 { return fmt.Errorf("removal requires Linux") }
