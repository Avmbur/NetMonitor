package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"time"

	"netmonitor/internal/collect"
	"netmonitor/internal/fw"
	pol "netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func (a *Agent) pollLoop() {
	for {
		if err := a.pollOnce(); err != nil {
			log.Printf("poll: %v", err)
			// An application or ACK failure is not evidence of a lost monitor.
			time.Sleep(2 * time.Second)
			continue
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (a *Agent) pollOnce() error {
	if err := a.reportPendingUpdate(); err != nil {
		log.Printf("update report: %v", err)
	}
	if err := a.reportPauses(); err != nil {
		log.Printf("pause report: %v", err)
	}
	started := time.Now()
	a.fwMu.RLock()
	rev := a.rev
	a.fwMu.RUnlock()
	var consumed []string
	if unlock, e := a.lockFirewall(); e == nil {
		if c, err := a.readControl(); err == nil {
			consumed = append([]string(nil), c.OnceUsed...)
		}
		unlock()
	}
	pr, err := a.exchangePoll(protocol.PollReq{Rev: rev, ConsumedOnce: consumed})
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) {
			if undoErr := a.rollbackAfterLoss(started); undoErr != nil {
				log.Printf("local rollback: %v", undoErr)
			}
		}
		return err
	}
	return a.applyPoll(pr)
}

func (a *Agent) exchangePoll(in protocol.PollReq) (protocol.PollRes, error) {
	var out protocol.PollRes
	raw, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequest(http.MethodPost, a.monitorURL()+"/v1/poll", bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return out, err
	}
	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("poll %s: %s", res.Status, b)
	}
	if err = json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	return out, nil
}

var localSSHPorts = func() []int { return collect.SSHListenPorts("") }

func policyFromPoll(pr protocol.PollRes, mon netip.Addr) (fw.Policy, error) {
	if pr.Model != 0 && pr.Model != 1 {
		return fw.Policy{}, fmt.Errorf("unsupported policy model %d", pr.Model)
	}
	// sshd ports are read here, not taken from the monitor: until it has this
	// host's report its snapshot knows only 22.
	rules := pol.ExpandStarterSSH(pr.Rules, localSSHPorts())
	p := fw.Policy{Managed: pr.Model == 1, Rules: rules, Groups: pr.Groups, Mode: pr.Mode, Monitor: mon}
	if p.Mode == "" {
		p.Mode = "allow"
	}
	var err error
	if p.Never, err = strictPrefixes(pr.NeverBlock); err != nil {
		return p, err
	}
	if p.BlockNets, err = strictPrefixes(pr.BlockNets); err != nil {
		return p, err
	}
	if p.AllowNets, err = strictPrefixes(pr.AllowNets); err != nil {
		return p, err
	}
	now := store.NowMS()
	for _, b := range pr.Blocks {
		if b.State != "active" {
			continue
		}
		var ip netip.Addr
		var err error
		if b.RemoteIP != "" {
			ip, err = netip.ParseAddr(b.RemoteIP)
		} else if b.LocalPort == 0 {
			err = fmt.Errorf("empty ban target")
		}
		if err != nil {
			return p, fmt.Errorf("ban address: %w", err)
		}
		if b.ExpiresAt > 0 && b.ExpiresAt <= now {
			continue
		}
		p.Blocks = append(p.Blocks, fw.Desired{LocalPort: b.LocalPort, BlockID: b.BlockID, Protocol: b.Protocol, Port: b.Port, IP: ip.Unmap(), ExpiresAtMS: b.ExpiresAt, Direction: b.Direction})
	}
	return p, nil
}
func strictPrefixes(ss []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			ip, e := netip.ParseAddr(s)
			if e != nil {
				return nil, fmt.Errorf("policy prefix %q: %w", s, e)
			}
			ip = ip.Unmap()
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// policyLocked and setPolicyLocked require fwMu.
func (a *Agent) policyLocked() fw.Policy {
	_, port := a.monitorAddr()
	return fw.Policy{Managed: a.managed, Rules: a.rules, Groups: a.groups, Blocks: a.applied, BlockNets: a.nets, AllowNets: a.allows, Never: a.never, Monitor: a.monitorIP(), MonitorPort: port, Mode: a.mode, DockerIfaces: a.dockerIfaces, DockerNets: a.dockerNets}
}
func (a *Agent) setPolicyLocked(p fw.Policy) {
	a.managed = p.Managed
	a.rules = p.Rules
	a.groups = p.Groups
	a.applied = p.Blocks
	a.nets = p.BlockNets
	a.allows = p.AllowNets
	a.never = p.Never
	a.mode = p.Mode
	a.dockerIfaces = append([]string(nil), p.DockerIfaces...)
	a.dockerNets = append([]netip.Prefix(nil), p.DockerNets...)
}
func (a *Agent) fillBridges(p *fw.Policy) {
	view := collect.LocalView(a.skipIfaces)
	p.DockerIfaces = append([]string(nil), view.BridgeIfaces...)
	p.DockerNets = append([]netip.Prefix(nil), view.BridgeNets...)
}

func (a *Agent) adoptViewLocked(pr protocol.PollRes) {
	a.lan, _ = strictPrefixes(pr.LAN)
	a.own, _ = strictPrefixes(pr.Own)
	a.observeDocker = pr.ObserveDocker
	if a.scan != nil {
		if pr.ScanPorts > 0 {
			a.scan.SetNeed(pr.ScanPorts)
		}
		if pr.ScanWindowMS > 0 {
			a.scan.SetWindow(time.Duration(pr.ScanWindowMS) * time.Millisecond)
		}
	}
}
func (a *Agent) applyPoll(pr protocol.PollRes) error {
	unlock, lockErr := a.lockFirewall()
	if lockErr != nil {
		return lockErr
	}
	if a.firewall == nil {
		a.firewall = fw.NewController()
	}
	status := protocol.ApplyStatus{Backend: a.firewall.Backend(), DesiredRev: pr.PolicyRev, AppliedRev: a.actualRev}
	if !pr.Authorized {
		// Pending/revoked agents may collect, but must not execute park policy.
		rev := a.rev
		unlock()
		_, err := a.exchangePoll(protocol.PollReq{Rev: rev, Status: &status})
		return err
	}
	damaged := a.actualRev != nil && !a.firewall.Alive()
	if damaged {
		a.actualRev = nil
	}
	a.adoptViewLocked(pr)
	p, err := policyFromPoll(pr, a.monitorIP())
	if err == nil {
		_, port := a.monitorAddr()
		p.MonitorPort = port
	}
	control, controlErr := a.readControl()
	if err == nil {
		err = controlErr
	}
	if err == nil {
		current := map[string]bool{}
		for _, id := range pr.LocalPauses {
			current[id] = true
		}
		for id, pause := range control.Pauses {
			if pause.Reported && !current[id] {
				delete(control.Pauses, id)
			}
		}
		p = filterPaused(p, control)
		keep := []string{}
		spent := map[string]bool{}
		for _, r := range p.Rules {
			if r.OnceUsed {
				spent[r.ID] = true
			}
		}
		for _, id := range control.OnceUsed {
			if !spent[id] {
				keep = append(keep, id)
			}
		}
		control.OnceUsed = keep
		p = markOnceUsed(p, control.OnceUsed)
	}
	if err == nil {
		a.fillBridges(&p)
		a.setContainerNets(p.DockerNets)
	}
	if err == nil && (a.actualRev == nil || *a.actualRev != pr.PolicyRev || a.fwError != "" || !reflect.DeepEqual(p, a.policyLocked())) {
		err = a.firewall.Apply(p)
		if err == nil {
			changed := changedBanIDs(a.applied, p.Blocks)
			if len(changed) > 0 {
				control.LastBefore = nil
				for _, old := range a.applied {
					for _, id := range changed {
						if blockKey(old) == id {
							control.LastBefore = append(control.LastBefore, old)
						}
					}
				}
				control.LastIDs = changed
				control.LastAtMS = store.NowMS()
			}

			a.setPolicyLocked(p)
			a.policyRev = pr.PolicyRev
			rev := pr.PolicyRev
			a.actualRev = &rev
			// The confirmed revision is saved with this policy, not the previous one.
			err = a.saveLocal(pr.PolicyRev, p, &control)
			if err == nil {
				a.rev = pr.PolicyRev
			}
		}
	}
	if err == nil {
		err = a.saveLocal(pr.PolicyRev, p, &control)
	}
	if err == nil && damaged {
		err = a.Enqueue("health", 10, protocol.HealthPayload{Kind: "firewall_restored", Note: "восстановлена локальная политика firewall"})
	}
	status.AppliedRev = a.actualRev
	// A locally paused ban is intentionally absent. Until the monitor knows
	// about that exception, claiming the entire desired revision would lie.
	if err == nil {
		for _, b := range pr.Blocks {
			pause, ok := control.Pauses[b.BlockID]
			if ok && !pause.Reported && b.State == "active" {
				err = fmt.Errorf("local pause awaits monitor acknowledgement")
				status.AppliedRev = nil
				break
			}
		}
	}
	a.fwError = ""
	if err != nil {
		a.fwError = err.Error()
		status.Error = err.Error()
	}
	var ack []string
	uninstall := ""
	updateID, updatePayload := "", ""
	for _, c := range pr.Commands {
		status.CommandIDs = append(status.CommandIDs, c.ID)
		// Снятие и обновление не зависят от политики.
		switch c.Kind {
		case "uninstall":
			uninstall = c.ID
		case "update":
			updateID, updatePayload = c.ID, c.Payload
		default:
			if err == nil {
				ack = append(ack, c.ID)
			}
		}
	}
	rev := a.rev
	unlock()
	_, reportErr := a.exchangePoll(protocol.PollReq{Rev: rev, Ack: ack, Status: &status})
	if uninstall != "" {
		// Scheduling never claims success; the durable worker confirms after cleanup.
		start := a.startRemoval
		if start == nil {
			start = a.scheduleUninstall
		}
		if removeErr := start(uninstall); removeErr != nil {
			_ = sendUninstallResult(a.client, a.monitorURL(), protocol.UninstallResult{CommandID: uninstall, Phase: "failed", Error: removeErr.Error()})
			return fmt.Errorf("schedule removal: %w", removeErr)
		}
	}
	if updateID != "" {
		start := a.startUpdate
		if start == nil {
			start = a.scheduleUpdate
		}
		if upErr := start(updateID, updatePayload); upErr != nil {
			return fmt.Errorf("schedule update: %w", upErr)
		}
	}
	if err != nil {
		if reportErr != nil {
			return fmt.Errorf("apply: %w; reporting: %v", err, reportErr)
		}
		return err
	}
	return reportErr
}

func changedBanIDs(old, now []fw.Desired) []string {
	had := map[string]fw.Desired{}
	for _, d := range old {
		had[blockKey(d)] = d
	}
	var ids []string
	for _, d := range now {
		if prev, ok := had[blockKey(d)]; !ok || !reflect.DeepEqual(prev, d) {
			ids = append(ids, blockKey(d))
		}
	}
	return ids
}
func (a *Agent) monitorIP() netip.Addr { ip, _ := a.monitorAddr(); return ip }
