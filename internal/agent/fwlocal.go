package agent

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"netmonitor/internal/filelock"
	"netmonitor/internal/fw"
	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"path/filepath"
	"reflect"
	"time"
)

type savedFW struct {
	Rev    int64     `json:"rev"`
	Policy fw.Policy `json:"policy"`
}
type localPause struct {
	RequestID string
	Reported  bool
	Reason    string
	Prior     *fw.Desired
}
type localControl struct {
	Pauses     map[string]localPause
	OnceUsed   []string
	LastIDs    []string
	LastBefore []fw.Desired
	LastAtMS   int64
}

func (a *Agent) lockFirewall() (func(), error) {
	a.fwMu.Lock()
	release, err := filelock.Acquire(filepath.Join(filepath.Dir(a.st.Path()), "firewall.lock"))
	if err != nil {
		a.fwMu.Unlock()
		return nil, err
	}
	if a.firewall == nil {
		a.firewall = fw.NewController()
	}
	return func() { release(); a.fwMu.Unlock() }, nil
}
func (a *Agent) readSnapshot() (savedFW, error) {
	var s savedFW
	var raw string
	err := a.st.DB.QueryRow("SELECT payload FROM local_policy WHERE object_key='desired'").Scan(&raw)
	if err == sql.ErrNoRows {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal([]byte(raw), &s)
	s.Policy.Monitor = a.monitorIP()
	return s, err
}
func (a *Agent) readControl() (localControl, error) {
	c := localControl{Pauses: map[string]localPause{}}
	raw, err := meta(a.st.DB, "fw_control")
	if err == sql.ErrNoRows {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(raw), &c)
	if c.Pauses == nil {
		c.Pauses = map[string]localPause{}
	}
	return c, err
}
func blockKey(d fw.Desired) string {
	if d.BlockID != "" {
		return d.BlockID
	}
	return "ip:" + d.IP.Unmap().String()
}
func markOnceUsed(p fw.Policy, ids []string) fw.Policy {
	spent := map[string]bool{}
	for _, id := range ids {
		spent[id] = true
	}
	for i := range p.Rules {
		if spent[p.Rules[i].ID] {
			p.Rules[i].OnceUsed = true
		}
	}
	return p
}

func filterPaused(p fw.Policy, c localControl) fw.Policy {
	var blocks []fw.Desired
	for _, b := range p.Blocks {
		if _, paused := c.Pauses[blockKey(b)]; !paused {
			blocks = append(blocks, b)
		}
	}
	for _, pause := range c.Pauses {
		if pause.Prior != nil && (pause.Prior.ExpiresAtMS == 0 || pause.Prior.ExpiresAtMS > store.NowMS()) {
			blocks = append(blocks, *pause.Prior)
		}
	}
	p.Blocks = blocks
	return p
}
func (a *Agent) saveLocal(rev int64, p fw.Policy, c *localControl) error {
	raw, err := json.Marshal(savedFW{Rev: rev, Policy: p})
	if err != nil {
		return err
	}
	var control []byte
	if c != nil {
		control, err = json.Marshal(c)
		if err != nil {
			return err
		}
	}
	return a.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO local_policy(object_key,kind,payload,desired_rev,applied_at_ms) VALUES('desired','fw',?,?,?) ON CONFLICT(object_key) DO UPDATE SET payload=excluded.payload,desired_rev=excluded.desired_rev,applied_at_ms=excluded.applied_at_ms", string(raw), rev, store.NowMS())
		if err != nil {
			return err
		}
		if c != nil {
			_, err = tx.Exec("INSERT INTO meta(k,v) VALUES('fw_control',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", string(control))
		}
		return err
	})
}
func (a *Agent) savePolicyLocked(rev int64, p fw.Policy) error { return a.saveLocal(rev, p, nil) }

func (a *Agent) consumeOnceLocked(id string) error {
	if id == "" {
		return nil
	}
	s, err := a.readSnapshot()
	if err != nil {
		return err
	}
	c, err := a.readControl()
	if err != nil {
		return err
	}
	for _, have := range c.OnceUsed {
		if have == id {
			return nil
		}
	}
	c.OnceUsed = append(c.OnceUsed, id)
	p := markOnceUsed(filterPaused(s.Policy, c), c.OnceUsed)
	if err = a.firewall.Apply(p); err != nil {
		return err
	}
	a.setPolicyLocked(p)
	return a.saveLocal(s.Rev, p, &c)
}
func (a *Agent) loadLocalFW() error {
	unlock, err := a.lockFirewall()
	if err != nil {
		return err
	}
	defer unlock()
	s, err := a.readSnapshot()
	if err != nil {
		return err
	}
	if s.Policy.Mode == "" {
		return nil
	}
	c, err := a.readControl()
	if err != nil {
		return err
	}
	p := filterPaused(s.Policy, c)
	_, port := a.monitorAddr()
	p.MonitorPort = port
	a.setPolicyLocked(p)
	a.rev = s.Rev
	a.policyRev = s.Rev
	if err = a.firewall.Apply(p); err != nil {
		a.fwError = err.Error()
		return err
	}
	rev := s.Rev
	a.actualRev = &rev
	a.fwError = ""
	return nil
}
func parsePrefixes(ss []string) []netip.Prefix { p, _ := strictPrefixes(ss); return p }

func (a *Agent) pauseLocked(s savedFW, c localControl, ids []string, restore []fw.Desired) error {
	for _, id := range ids {
		pause := localPause{RequestID: idgen.NewV7(), Reason: "rollback"}
		for _, old := range restore {
			if blockKey(old) == id {
				copy := old
				pause.Prior = &copy
				break
			}
		}
		c.Pauses[id] = pause
	}

	p := filterPaused(s.Policy, c)
	if err := a.saveLocal(s.Rev, p, &c); err != nil {
		return err
	}
	a.setPolicyLocked(p)
	a.policyRev = s.Rev
	a.actualRev = nil
	if err := a.firewall.Apply(p); err != nil {
		a.fwError = err.Error()
		return err
	}
	rev := s.Rev
	a.actualRev = &rev
	a.rev = rev
	a.fwError = ""
	return nil
}
func (a *Agent) rollbackAfterLoss(started time.Time) error {
	unlock, err := a.lockFirewall()
	if err != nil {
		return err
	}
	defer unlock()
	c, err := a.readControl()
	if err != nil {
		return err
	}
	dt := started.UnixMilli() - c.LastAtMS
	if dt < 0 || dt >= 60000 || len(c.LastIDs) == 0 {
		return nil
	}
	s, err := a.readSnapshot()
	if err != nil {
		return err
	}
	ids := append([]string(nil), c.LastIDs...)
	c.LastIDs = nil
	return a.pauseLocked(s, c, ids, c.LastBefore)
}
func (a *Agent) reportPauses() error {
	// Never hold the firewall lock while waiting on the network.
	unlock, err := a.lockFirewall()
	if err != nil {
		return err
	}
	c, err := a.readControl()
	unlock()
	if err != nil {
		return err
	}
	for id, pause := range c.Pauses {
		if pause.Reported {
			continue
		}
		body, err := json.Marshal(protocol.LocalUnblock{RequestID: pause.RequestID, BlockIDs: []string{id}, Reason: pause.Reason})
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, a.monitorURL()+"/v1/local-unblock", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := a.client.Do(req)
		if err != nil {
			return err
		}
		b, readErr := io.ReadAll(io.LimitReader(res.Body, 65536))
		res.Body.Close()
		if readErr != nil {
			return readErr
		}
		if res.StatusCode != 200 {
			return fmt.Errorf("local-unblock %s: %s", res.Status, b)
		}
		unlock, err = a.lockFirewall()
		if err != nil {
			return err
		}
		current, e := a.readControl()
		if e == nil {
			v, ok := current.Pauses[id]
			if ok && v.RequestID == pause.RequestID {
				v.Reported = true
				current.Pauses[id] = v
				var raw []byte
				raw, e = json.Marshal(current)
				if e == nil {
					e = a.st.Update(func(tx *sql.Tx) error {
						_, e := tx.Exec("INSERT INTO meta(k,v) VALUES('fw_control',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", string(raw))
						return e
					})
				}
			}
		}
		unlock()
		if e != nil {
			return e
		}
	}
	return nil
}
func (a *Agent) reconcileOnce() error {
	unlock, err := a.lockFirewall()
	if err != nil {
		return err
	}
	defer unlock()
	s, err := a.readSnapshot()
	if err != nil {
		return err
	}
	if s.Policy.Mode == "" && a.mode == "" {
		return nil
	}
	c, err := a.readControl()
	if err != nil {
		return err
	}
	p := filterPaused(s.Policy, c)
	if p.Mode == "" {
		p = filterPaused(a.policyLocked(), c)
		s.Rev = a.policyRev
	}
	if a.firewall.Alive() && a.actualRev != nil && reflect.DeepEqual(p, a.policyLocked()) {
		return nil
	}
	a.actualRev = nil
	a.setPolicyLocked(p)
	a.policyRev = s.Rev
	if err = a.firewall.Apply(p); err != nil {
		a.fwError = err.Error()
		return err
	}
	rev := s.Rev
	a.actualRev = &rev
	if err = a.savePolicyLocked(rev, p); err != nil {
		a.fwError = err.Error()
		return err
	}
	a.rev = rev
	a.fwError = ""
	if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "firewall_restored", Note: "восстановлена локальная политика firewall"}); err != nil {
		return err
	}
	return nil
}
func (a *Agent) watchdog() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		if err := a.reconcileOnce(); err != nil {
			log.Printf("firewall restore: %v", err)
		}
	}
}

// Restore needs only the local snapshot; it neither enrolls nor contacts a monitor.
func Restore(dataDir string) error {
	st, err := store.OpenAgent(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	monitor, err := meta(st.DB, "monitor")
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	a := &Agent{cfg: Config{DataDir: dataDir, Monitor: monitor}, st: st}
	return a.loadLocalFW()
}
