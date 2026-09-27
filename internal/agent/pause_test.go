package agent

import (
	"database/sql"
	"encoding/json"
	"errors"
	"netmonitor/internal/protocol"
	"testing"
	"time"
)

func twoBans() protocol.PollRes {
	p := policy(1)
	p.Blocks[0].BlockID = "old"
	b := p.Blocks[0]
	b.BlockID = "new"
	b.RemoteIP = "198.18.0.3"
	p.Blocks = append(p.Blocks, b)
	return p
}
func TestOfflinePauseSurvivesDaemonAndRestart(t *testing.T) {
	a, f, _, code := agentFixture(t)
	p := twoBans()
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	*code = 503
	cli := &Agent{st: a.st, cfg: a.cfg, firewall: f}
	snap, err := cli.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := cli.readControl()
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.pauseLocked(snap, ctrl, []string{"new"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.policy.Blocks) != 1 || f.policy.Blocks[0].BlockID != "old" {
		t.Fatal("wrong local removal")
	}
	if err := a.reconcileOnce(); err != nil {
		t.Fatal(err)
	}
	if len(f.policy.Blocks) != 1 {
		t.Fatal("daemon revived pause")
	}
	*code = 200
	if err := a.applyPoll(p); err == nil {
		t.Fatal("unreported pause acknowledged as applied")
	}
	if len(f.policy.Blocks) != 1 {
		t.Fatal("stale poll revived pause")
	}
	restarted := &Agent{st: a.st, cfg: a.cfg, firewall: &fakeFW{}}
	if err := restarted.loadLocalFW(); err != nil || len(restarted.applied) != 1 {
		t.Fatal("restart revived pause", err)
	}
	// The same address in a new, explicit ban is not a permanent exemption.
	p.Blocks[1].BlockID = "future"
	p.PolicyRev++
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	if len(f.policy.Blocks) != 2 {
		t.Fatal("pause widened to future ban")
	}
}
func TestPauseIntentFailureDoesNotTouchKernel(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	if err := a.applyPoll(twoBans()); err != nil {
		t.Fatal(err)
	}
	n := f.calls
	a.st.DB.Exec("CREATE TRIGGER fail_pause BEFORE INSERT ON meta WHEN new.k='fw_control' BEGIN SELECT RAISE(ABORT,'full'); END")
	snap, err := a.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := a.readControl()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range snap.Policy.Blocks {
		ids = append(ids, blockKey(b))
	}
	if err := a.pauseLocked(snap, ctrl, ids, nil); err == nil {
		t.Fatal("hidden failure")
	}
	if f.calls != n {
		t.Fatal("kernel changed without durable intent")
	}
}
func TestPauseApplyFailureIsRetried(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	a.applyPoll(twoBans())
	f.err = errors.New("denied")
	snap, err := a.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := a.readControl()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.pauseLocked(snap, ctrl, []string{"new"}, nil); err == nil {
		t.Fatal("hidden apply failure")
	}
	f.err = nil
	if err := a.reconcileOnce(); err != nil || len(f.policy.Blocks) != 1 {
		t.Fatal("durable intent lost", err)
	}
}
func TestRollbackLastOnlyAndLateLoss(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	p := twoBans()
	old := p
	old.Blocks = p.Blocks[:1]
	if err := a.applyPoll(old); err != nil {
		t.Fatal(err)
	}
	p.PolicyRev = 2
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	// A reboot preserves the exact change and its timestamp.
	restarted := &Agent{st: a.st, cfg: a.cfg, firewall: f}
	if err := restarted.loadLocalFW(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.rollbackAfterLoss(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.policy.Blocks) != 1 || f.policy.Blocks[0].BlockID != "old" {
		t.Fatal("rollback removed older protection")
	}
	p.Blocks[1].BlockID = "late"
	p.PolicyRev++
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	if err := a.rollbackAfterLoss(time.Now().Add(61 * time.Second)); err != nil || len(f.policy.Blocks) != 2 {
		t.Fatal("late loss removed old ban", err)
	}
}
func TestPauseDeliveryRetriedUntilAcknowledged(t *testing.T) {
	a, _, _, code := agentFixture(t)
	a.applyPoll(twoBans())
	snap, err := a.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := a.readControl()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, b := range snap.Policy.Blocks {
		ids = append(ids, blockKey(b))
	}
	if err := a.pauseLocked(snap, ctrl, ids, nil); err != nil {
		t.Fatal(err)
	}
	*code = 503
	if err := a.reportPauses(); err == nil {
		t.Fatal("report failure hidden")
	}
	c, _ := a.readControl()
	for _, p := range c.Pauses {
		if p.Reported {
			t.Fatal("unacknowledged marked sent")
		}
	}
	*code = 200
	if err := a.reportPauses(); err != nil {
		t.Fatal(err)
	}
	c, _ = a.readControl()
	for _, p := range c.Pauses {
		if !p.Reported {
			t.Fatal("ACK not saved")
		}
	}
}
func TestExpiredLocalBanRetainsAbsoluteDeadline(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	p := twoBans()
	p.Blocks[0].ExpiresAt = time.Now().Add(-time.Hour).UnixMilli()
	a.applyPoll(p)
	if len(f.policy.Blocks) != 1 {
		t.Fatal("expired input revived")
	}
	// Simulate a saved policy expiring while the agent was off.
	snapshot, _ := a.readSnapshot()
	snapshot.Policy.Blocks[0].ExpiresAtMS = time.Now().Add(-time.Second).UnixMilli()
	raw, _ := json.Marshal(snapshot)
	a.st.Update(func(tx *sql.Tx) error { _, e := tx.Exec("UPDATE local_policy SET payload=?", string(raw)); return e })
	restarted := &Agent{st: a.st, cfg: a.cfg, firewall: &fakeFW{}}
	if err := restarted.loadLocalFW(); err != nil {
		t.Fatal(err)
	}
	if restarted.applied[0].ExpiresAtMS >= time.Now().UnixMilli() {
		t.Fatal("deadline renewed")
	}
}

func TestRollbackExtensionKeepsPreviousBan(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	p := twoBans()
	p.Blocks = p.Blocks[:1]
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	before := p.Blocks[0].ExpiresAt
	p.Blocks[0].ExpiresAt += 3600000
	p.PolicyRev++
	if err := a.applyPoll(p); err != nil {
		t.Fatal(err)
	}
	if err := a.rollbackAfterLoss(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.policy.Blocks) != 1 || f.policy.Blocks[0].ExpiresAtMS != before {
		t.Fatal("extension rollback removed older ban", f.policy)
	}
	restarted := &Agent{st: a.st, cfg: a.cfg, firewall: &fakeFW{}}
	if err := restarted.loadLocalFW(); err != nil || len(restarted.applied) != 1 || restarted.applied[0].ExpiresAtMS != before {
		t.Fatal("previous condition lost", err)
	}
	// Monitor's explicit removal after it confirmed local pause releases the old condition.
	if err := a.reportPauses(); err != nil {
		t.Fatal(err)
	}
	p.Blocks = nil
	p.PolicyRev++
	if err := a.applyPoll(p); err != nil || len(f.policy.Blocks) != 0 {
		t.Fatal("removed block retained", err)
	}
}
