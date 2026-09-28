package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"netmonitor/internal/protocol"
	"netmonitor/internal/tlsutil"
)

// Each step must succeed. The worker, not the agent being stopped, sends completion.
const uninstallScript = `set -eu
for unit in nmagent.service nmagent-restore.service; do
 state=$(systemctl show "$unit" -p LoadState --value)
 if [ "$state" != "not-found" ]; then
  systemctl disable --now "$unit"
  state=$(systemctl show "$unit" -p ActiveState --value)
  case "$state" in inactive|failed) ;; *) echo "$unit is still running" >&2; exit 1 ;; esac
 fi
done
tables=$(nft list tables)
if printf '%s\n' "$tables" | grep -qx 'table inet netmon'; then
 nft delete table inet netmon
fi
tables=$(nft list tables)
if printf '%s\n' "$tables" | grep -qx 'table inet netmon'; then
 echo 'netmon table remains' >&2; exit 1
fi
rm -f /etc/systemd/system/nmagent.service /etc/systemd/system/nmagent-restore.service /usr/local/bin/nmagent /usr/local/bin/nmagent.stage /usr/local/bin/nmagent.next
rm -rf /var/lib/nmagent
systemctl daemon-reload
`

type uninstallJob struct {
	CommandID     string
	Monitor       string
	CA, Cert, Key []byte
}

func removalClient(job uninstallJob) (*http.Client, error) {
	cfg, err := tlsutil.ClientTLSConfig(job.CA, job.Cert, job.Key)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport:     &http.Transport{TLSClientConfig: cfg},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func sendUninstallResult(client *http.Client, monitor string, in protocol.UninstallResult) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := client.Post(monitor+"/v1/uninstall-result", "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("removal report: HTTP %d", res.StatusCode)
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("removal was not acknowledged")
	}
	return nil
}

// The marker is written only after verified cleanup, before contacting the monitor.
// After a restart it skips cleanup and replays completion without needing an agent row.
func runUninstallJob(done bool, cleanup, markDone func() error, report func(string, string) error) error {
	if !done {
		if err := report("prepare", ""); err != nil {
			return err
		}
		if err := cleanup(); err != nil {
			message := err.Error()
			if len(message) > 4000 {
				message = message[:4000]
			}
			_ = report("failed", message)
			return err
		}
		if err := markDone(); err != nil {
			return err
		}
	}
	return report("complete", "")
}
