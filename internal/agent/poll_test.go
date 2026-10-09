package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"netmonitor/internal/fw"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

type fakeFW struct {
	err    error
	calls  int
	alive  bool
	policy fw.Policy
}

func (f *fakeFW) Backend() string { return "nftables" }
func (f *fakeFW) Apply(p fw.Policy) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.policy = p
	f.alive = true
	return nil
}
func (f *fakeFW) Alive() bool { return f.alive }
func agentFixture(t *testing.T) (*Agent, *fakeFW, *[]protocol.PollReq, *int) {
	t.Helper()
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reports := []protocol.PollReq{}
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in protocol.PollReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
		}
		reports = append(reports, in)
		w.WriteHeader(code)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	f := &fakeFW{alive: true}
	return &Agent{st: st, cfg: Config{Monitor: srv.URL}, client: srv.Client(), firewall: f}, f, &reports, &code
}
func policy(rev int64) protocol.PollRes {
	return protocol.PollRes{Authorized: true, PolicyRev: rev, Mode: "allow", Commands: []protocol.Command{{ID: "cmd"}},
		Blocks: []protocol.BlockView{{RemoteIP: "198.18.0.2", Direction: "both", State: "active", ExpiresAt: store.NowMS() + 60000}}}
}
func TestFailedApplyNeverAcknowledgesOrOverwritesSnapshot(t *testing.T) {
	a, f, reports, _ := agentFixture(t)
	one := policy(1)
	if err := a.applyPoll(one); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := a.st.DB.QueryRow("SELECT payload FROM local_policy WHERE object_key='desired'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	f.err = errors.New("nft: permission denied")
	two := policy(2)
	two.Mode = "learn"
	if err := a.applyPoll(two); err == nil {
		t.Fatal("failure hidden")
	}
	if a.rev != 1 || a.mode != "allow" || *a.actualRev != 1 {
		t.Fatal("failed state reported as applied")
	}
	last := (*reports)[len(*reports)-1]
	if len(last.Ack) != 0 || last.Status.Error == "" || *last.Status.AppliedRev != 1 || last.Status.DesiredRev != 2 {
		t.Fatalf("false ACK: %+v", last)
	}
	var after string
	a.st.DB.QueryRow("SELECT payload FROM local_policy WHERE object_key='desired'").Scan(&after)
	if before != after {
		t.Fatal("good local policy overwritten by failed policy")
	}
	f.err = nil
	if err := a.applyPoll(two); err != nil {
		t.Fatal(err)
	}
	if a.rev != 2 || a.mode != "learn" {
		t.Fatal("recovery failed")
	}
	var saved savedFW
	a.st.DB.QueryRow("SELECT payload FROM local_policy WHERE object_key='desired'").Scan(&after)
	if err := json.Unmarshal([]byte(after), &saved); err != nil || saved.Rev != 2 {
		t.Fatal("saved old revision", err)
	}
}
func TestLostAckRetriesWithoutReapplyingOrChangingExpiry(t *testing.T) {
	a, f, reports, code := agentFixture(t)
	pr := policy(7)
	*code = 503
	if err := a.applyPoll(pr); err == nil {
		t.Fatal("ACK HTTP error ignored")
	}
	expires := f.policy.Blocks[0].ExpiresAtMS
	*code = 200
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || f.policy.Blocks[0].ExpiresAtMS != expires {
		t.Fatal("retry reapplied policy or extended TTL")
	}
	if len((*reports)[1].Ack) != 1 {
		t.Fatal("ACK not retried")
	}
}
func TestPendingPolicyDoesNotRun(t *testing.T) {
	a, f, reports, _ := agentFixture(t)
	pr := policy(1)
	pr.Authorized = false
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if f.calls != 0 || len((*reports)[0].Ack) != 0 || a.actualRev != nil {
		t.Fatal("pending applied park policy")
	}
}
func TestSnapshotWriteFailureNeverAck(t *testing.T) {
	a, _, reports, _ := agentFixture(t)
	if _, err := a.st.DB.Exec("CREATE TRIGGER fail_snapshot BEFORE INSERT ON local_policy BEGIN SELECT RAISE(ABORT,'disk failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := a.applyPoll(policy(1)); err == nil {
		t.Fatal("snapshot error ignored")
	}
	st := (*reports)[0]
	if len(st.Ack) > 0 || st.Status.Error == "" || st.Status.AppliedRev == nil || *st.Status.AppliedRev != 1 {
		t.Fatal("incorrect actual kernel result on persistence failure")
	}
}
func TestRestoreFailureAndRecovery(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	pr := policy(9)
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	b := &Agent{st: a.st, cfg: a.cfg, firewall: &fakeFW{err: errors.New("nft disappeared")}}
	if err := b.loadLocalFW(); err == nil || b.actualRev != nil {
		t.Fatal("failed startup restore claimed success")
	}
	b.firewall = f
	if err := b.reconcileOnce(); err != nil || b.actualRev == nil || *b.actualRev != 9 {
		t.Fatal("restore retry failed", err)
	}
	f.alive = false
	f.err = errors.New("denied")
	if err := b.reconcileOnce(); err == nil || b.actualRev != nil {
		t.Fatal("missing table still reported as applied")
	}
}
func TestConcurrentPolicyReadersAndWatchdog(t *testing.T) {
	a, _, _, _ := agentFixture(t)
	if err := a.applyPoll(policy(1)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				a.fwMu.RLock()
				_ = a.policyLocked()
				a.fwMu.RUnlock()
				if err := a.reconcileOnce(); err != nil {
					t.Error(err)
				}
				_ = a.flowAllowedForTest()
			}
		}()
	}
	for i := 0; i < 15; i++ {
		if err := a.applyPoll(policy(int64(i + 2))); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func (a *Agent) flowAllowedForTest() bool {
	a.fwMu.RLock()
	defer a.fwMu.RUnlock()
	return a.mode != "" && a.monitorIP() != netip.Addr{}
}

func TestLocalPolicyPreservesIdentityAndExpiry(t *testing.T) {
	a, _, _, _ := agentFixture(t)
	pr := policy(5)
	pr.Blocks[0].BlockID = "ban-identity"
	pr.NeverBlock = []string{"198.18.0.90/32"}
	pr.AllowNets = []string{"198.18.1.0/24"}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	reopened := &Agent{st: a.st, cfg: a.cfg, firewall: &fakeFW{}}
	if err := reopened.loadLocalFW(); err != nil {
		t.Fatal(err)
	}
	if reopened.applied[0].BlockID != "ban-identity" || reopened.applied[0].ExpiresAtMS != pr.Blocks[0].ExpiresAt || len(reopened.never) != 1 || len(reopened.allows) != 1 {
		t.Fatal("local policy lost fields")
	}
	p, err := policyFromPoll(protocol.PollRes{Mode: "allow", Blocks: []protocol.BlockView{{BlockID: "exact", RemoteIP: "198.18.0.5", Protocol: "tcp", Port: 22, Direction: "in", State: "active"}}}, netip.Addr{})
	if err != nil || p.Blocks[0].Protocol != "tcp" || p.Blocks[0].Port != 22 || p.Blocks[0].Direction != "in" {
		t.Fatal("wire fields lost", p, err)
	}
}

func TestUnreportedLocalPauseDoesNotClaimDesiredApplied(t *testing.T) {
	a, f, reports, _ := agentFixture(t)
	pr := policy(7)
	pr.Blocks[0].BlockID = "paused-ban"
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	snap, err := a.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := a.readControl()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.pauseLocked(snap, ctrl, []string{"paused-ban"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.applyPoll(pr); err == nil {
		t.Fatal("unreported exception claimed applied")
	}
	last := (*reports)[len(*reports)-1]
	if len(last.Ack) != 0 || last.Status.AppliedRev != nil || last.Status.Error == "" || len(f.policy.Blocks) != 0 {
		t.Fatalf("false ACK or ban restored: %+v", last)
	}
	c, err := a.readControl()
	if err != nil {
		t.Fatal(err)
	}
	v := c.Pauses["paused-ban"]
	v.Reported = true
	c.Pauses["paused-ban"] = v
	snap, err = a.readSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.saveLocal(snap.Rev, snap.Policy, &c); err != nil {
		t.Fatal(err)
	}
	pr.LocalPauses = []string{"paused-ban"}
	pr.Blocks = nil
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	last = (*reports)[len(*reports)-1]
	if len(last.Ack) != 1 || last.Status.Error != "" {
		t.Fatal("known pause prevented recovery")
	}
}

func TestPollRepairProducesOneHealthEvent(t *testing.T) {
	a, f, _, _ := agentFixture(t)
	pr := policy(8)
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	f.alive = false
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, it := range a.plan.copy() {
		if it.kind == "health" && strings.Contains(it.payload, "firewall_restored") {
			n++
		}
	}
	if n != 1 {
		t.Fatal("repair event count", n)
	}
}
