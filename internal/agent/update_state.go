package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"netmonitor/internal/protocol"
)

type agentUpdateState struct {
	CommandID string
	Version   string
	Phase     string
	Error     string
	Acked     bool
}

func (j agentUpdateState) unit() string {
	sum := sha256.Sum256([]byte(j.CommandID))
	return "nmagent-update-" + hex.EncodeToString(sum[:12]) + ".service"
}

func readUpdateState(dir string) (*agentUpdateState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "update.state"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state agentUpdateState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.CommandID == "" {
		return nil, fmt.Errorf("empty update command")
	}
	return &state, nil
}

func saveUpdateState(dir string, state *agentUpdateState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".update-state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "update.state")); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}

// Only the updater's terminal verdict permits completion, never the version alone.
// The result is durable before the first send; Acked is durable before reuse.
func reconcileUpdate(dir, current, updating string, active func(string) (bool, error), report func(protocol.UpdateResult) error) (bool, error) {
	state, err := readUpdateState(dir)
	if err != nil || state == nil {
		return false, err
	}
	if state.Acked {
		return true, nil
	}
	if state.Phase == "" {
		raw, readErr := os.ReadFile(filepath.Join(dir, "update.outcome"))
		if readErr != nil && !os.IsNotExist(readErr) {
			return false, readErr
		}
		switch strings.TrimSpace(string(raw)) {
		case "verified":
			if updateVersionLess(current, state.Version) {
				state.Phase = "failed"
				state.Error = fmt.Sprintf("после обновления агент всё ещё %s, а релиз %s: версия в сборке не совпадает с меткой", current, state.Version)
			} else {
				state.Phase = "complete"
			}
		case "rolledback":
			state.Phase = "failed"
			state.Error = fmt.Sprintf("сборка %s не запустилась, возвращена прежняя %s", state.Version, current)
		case "failed":
			state.Phase = "failed"
			state.Error = "обновление прервано или откат не завершён; проверь службу агента"
		case "":
			// The initiating process must not mistake its own marker for a failed restart.
			if updating == state.CommandID {
				return false, nil
			}
			running, err := active(state.unit())
			if err != nil {
				return false, err
			}
			if running {
				return false, nil
			}
			state.Phase = "failed"
			state.Error = "обновление прервано до проверки запуска; повторная установка этой команды запрещена"
		default:
			return false, fmt.Errorf("unknown update outcome")
		}
		if err := saveUpdateState(dir, state); err != nil {
			return false, err
		}
	}
	if err := report(protocol.UpdateResult{CommandID: state.CommandID, Phase: state.Phase, Error: state.Error}); err != nil {
		return false, err
	}
	state.Acked = true
	if err := saveUpdateState(dir, state); err != nil {
		return false, err
	}
	return true, nil
}

func (a *Agent) reportPendingUpdate() error {
	if a.cfg.DataDir == "" {
		return nil
	}
	finished, err := reconcileUpdate(a.cfg.DataDir, Version, a.updating, updateUnitActive, func(result protocol.UpdateResult) error {
		return sendUpdateResult(a.client, a.monitorURL(), result)
	})
	if finished {
		a.updating = ""
	}
	return err
}
