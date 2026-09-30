//go:build linux

package agent

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"netmonitor/internal/svcnet"
)

func updateUnitActive(unit string) (bool, error) {
	out, err := exec.Command("systemctl", "show", unit, "-p", "ActiveState", "--value").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("update service status: %w: %s", err, out)
	}
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "deactivating", "reloading":
		return true, nil
	case "inactive", "failed":
		return false, nil
	default:
		return false, fmt.Errorf("unknown update service state: %s", out)
	}
}

func (a *Agent) scheduleUpdate(commandID, payload string) error {
	// First: a redelivered command must not interpret this process's attempt as failure.
	if a.updating == commandID {
		return nil
	}
	if err := a.reportPendingUpdate(); err != nil {
		return err
	}
	previous, err := readUpdateState(a.cfg.DataDir)
	if err != nil {
		return err
	}
	if previous != nil {
		if previous.CommandID == commandID {
			return nil
		}
		if !previous.Acked {
			return fmt.Errorf("previous update is still pending")
		}
	}
	spec, err := parseUpdatePayload(payload)
	state := &agentUpdateState{CommandID: commandID, Version: spec.Version}
	if err != nil {
		state.Phase = "failed"
		state.Error = err.Error()
		if e := saveUpdateState(a.cfg.DataDir, state); e != nil {
			return e
		}
		return a.reportPendingUpdate()
	}
	// Remove only the acknowledged previous job's verdict.
	outcome := filepath.Join(a.cfg.DataDir, "update.outcome")
	if err := os.Remove(outcome); err != nil && !os.IsNotExist(err) {
		return err
	}
	if !updateVersionLess(Version, spec.Version) {
		state.Phase = "complete"
	}
	if err := saveUpdateState(a.cfg.DataDir, state); err != nil {
		return err
	}
	if state.Phase != "" {
		return a.reportPendingUpdate()
	}
	if err := a.launchUpdate(*state, spec, outcome); err != nil {
		state.Phase = "failed"
		state.Error = err.Error()
		if len(state.Error) > 4000 {
			state.Error = state.Error[:4000]
		}
		if saveErr := saveUpdateState(a.cfg.DataDir, state); saveErr != nil {
			return saveErr
		}
		return a.reportPendingUpdate()
	}
	a.updating = commandID
	return nil
}

func (a *Agent) launchUpdate(state agentUpdateState, spec updatePayload, outcome string) error {
	url, sum, err := spec.asset(runtime.GOARCH)
	if err != nil {
		return err
	}
	bin, err := downloadAgentBinary(url, sum, runtime.GOARCH)
	if err != nil {
		return err
	}
	if err := os.WriteFile("/usr/local/bin/nmagent.next", bin, 0755); err != nil {
		return err
	}
	cmd := exec.Command("systemd-run", "--unit="+state.unit(), "--collect", "sh", "-c", updateScript, "nm-update-agent", outcome)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, out)
	}
	return nil
}

func downloadAgentBinary(url, sum, arch string) ([]byte, error) {
	// Адрес GitHub вписывается в фильтр этого агента до соединения.
	client := svcnet.Client(admitLocal, 3*time.Minute)
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("комплект: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 80<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 80<<20 {
		return nil, fmt.Errorf("комплект слишком большой")
	}
	if err := checkSum(body, sum); err != nil {
		return nil, err
	}
	return extractAgentBinary(bytes.NewReader(body), arch)
}
