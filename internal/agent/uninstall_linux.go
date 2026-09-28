//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"netmonitor/internal/protocol"
)

const uninstallDir = "/var/lib/nmagent-uninstall"
const uninstallUnitPath = "/etc/systemd/system/nmagent-uninstall.service"
const uninstallUnit = `[Unit]
Description=Finish NetMonitor agent removal
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/var/lib/nmagent-uninstall/worker uninstall-worker
Restart=on-failure
RestartSec=15
UMask=0077

[Install]
WantedBy=multi-user.target
`

func uninstallSystemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func (a *Agent) scheduleUninstall(commandID string) error {
	if filepath.Clean(a.cfg.DataDir) != "/var/lib/nmagent" {
		return fmt.Errorf("automatic removal requires /var/lib/nmagent")
	}
	if a.firewall.Backend() != "nftables" {
		return fmt.Errorf("automatic removal requires nftables; use manual cleanup for this backend")
	}
	if err := os.MkdirAll(uninstallDir, 0700); err != nil {
		return err
	}
	// Hold a lock shared with the worker; redelivery must not replace its executable.
	lock, err := os.OpenFile(filepath.Join(uninstallDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	jobPath := filepath.Join(uninstallDir, "job.json")
	if raw, err := os.ReadFile(jobPath); err == nil {
		var previous uninstallJob
		if err := json.Unmarshal(raw, &previous); err != nil {
			return err
		}
		if previous.CommandID != commandID {
			return fmt.Errorf("another removal is pending")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		job := uninstallJob{CommandID: commandID, Monitor: a.monitorURL()}
		for name, into := range map[string]*[]byte{"ca.crt": &job.CA, "client.crt": &job.Cert, "client.key": &job.Key} {
			raw, err := os.ReadFile(filepath.Join(a.cfg.DataDir, "tls", name))
			if err != nil {
				return err
			}
			*into = raw
		}
		client, err := removalClient(job)
		if err != nil {
			return err
		}
		client.CloseIdleConnections()
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		binary, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err := writeUninstallFile(filepath.Join(uninstallDir, "worker"), binary, 0700); err != nil {
			return err
		}
		raw, err := json.Marshal(job)
		if err != nil {
			return err
		}
		if err := writeUninstallFile(jobPath, raw, 0600); err != nil {
			return err
		}
	}
	if err := writeUninstallFile(uninstallUnitPath, []byte(uninstallUnit), 0644); err != nil {
		return err
	}
	if err := uninstallSystemctl("daemon-reload"); err != nil {
		return err
	}
	return uninstallSystemctl("enable", "--now", "--no-block", "nmagent-uninstall.service")
}

// Atomic, synced state survives worker crashes and machine reboots.
func writeUninstallFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".stage"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func RunUninstallWorker() error {
	lock, err := os.OpenFile(filepath.Join(uninstallDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, err := os.ReadFile(filepath.Join(uninstallDir, "job.json"))
	if err != nil {
		return err
	}
	var job uninstallJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return err
	}
	client, err := removalClient(job)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	marker := filepath.Join(uninstallDir, "removed")
	_, err = os.Stat(marker)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	done := err == nil
	err = runUninstallJob(done, func() error {
		out, err := exec.Command("sh", "-c", uninstallScript).CombinedOutput()
		if err != nil {
			return fmt.Errorf("removal: %w: %s", err, out)
		}
		return nil
	}, func() error { return writeUninstallFile(marker, []byte("removed\n"), 0600) },
		func(phase, message string) error {
			return sendUninstallResult(client, job.Monitor, protocol.UninstallResult{CommandID: job.CommandID, Phase: phase, Error: message})
		})
	if err != nil {
		return err
	}
	// Only the acknowledgement permits deleting the durable reporter.
	if err := uninstallSystemctl("disable", "nmagent-uninstall.service"); err != nil {
		return err
	}
	if err := os.Remove(uninstallUnitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := uninstallSystemctl("daemon-reload"); err != nil {
		return err
	}
	return os.RemoveAll(uninstallDir)
}
