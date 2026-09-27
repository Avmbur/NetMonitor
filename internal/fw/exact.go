package fw

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"netmonitor/internal/policy"
	"strings"
	"time"
)

func onceSetName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "o" + hex.EncodeToString(sum[:6])
}

func processTerms(r policy.Rule) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, b := range r.Match.Bindings {
		if !policy.DedicatedCgroup(b.Cgroup) {
			continue
		}
		term, err := policy.CgroupMatch(b.Cgroup)
		if err != nil {
			return nil, err
		}
		if !seen[term] {
			seen[term] = true
			out = append(out, term)
		}
	}
	if len(out) == 0 && r.Match.Bound() {
		return nil, nil
	}
	if len(out) == 0 {
		return []string{""}, nil
	}
	return out, nil
}

// emitPolicyRules renders every condition for both the original packet and its
// reply. Direction describes the connection initiator, not the current packet.
func emitPolicyRules(rs []policy.Rule, add func(string, string)) error {
	for _, r := range policy.Ordered(rs) {
		if !r.Enabled {
			continue
		}
		if policy.Inert(r) {
			continue
		}
		if err := policy.Executable(r); err != nil {
			continue
		}
		m := r.Match
		if m.Networks != nil && len(m.Networks) == 0 {
			continue
		}
		proc, err := processTerms(r)
		if err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if proc == nil {
			continue
		}
		dirs := []string{"in", "out"}
		if m.Direction == "in" || m.Direction == "out" {
			dirs = []string{m.Direction}
		}
		nets := m.Networks
		if nets == nil {
			nets = []string{""}
		}
		for _, dir := range dirs {
			for _, reply := range []bool{false, true} {
				if dir == "in" && !reply && len(proc) > 0 && proc[0] != "" && m.LocalPort == 0 && m.AnyPort == 0 {
					continue
				}
				ch := "output"
				remote, lp, rp := "daddr", "sport", "dport"
				ctdir := "original"
				if dir == "in" {
					ch = "input"
					remote, lp, rp = "saddr", "dport", "sport"
				}
				if reply {
					ctdir = "reply"
					if ch == "input" {
						ch = "output"
					} else {
						ch = "input"
					}
					if remote == "saddr" {
						remote = "daddr"
					} else {
						remote = "saddr"
					}
					lp, rp = rp, lp
				}
				for _, n := range nets {
					terms := []string{"ct direction " + ctdir}
					if n != "" {
						fam := "ip"
						if strings.Contains(n, ":") {
							fam = "ip6"
						}
						terms = append(terms, fam+" "+remote+" "+n)
					}
					proto := m.Protocol
					if proto == "icmpv6" {
						proto = "ipv6-icmp"
					}
					if proto != "" && proto != "any" {
						terms = append(terms, "meta l4proto "+proto)
					}
					if m.LocalPort > 0 {
						terms = append(terms, fmt.Sprintf("%s %s %d", proto, lp, m.LocalPort))
					}
					if m.RemotePort > 0 {
						terms = append(terms, fmt.Sprintf("%s %s %d", proto, rp, m.RemotePort))
					}
					if r.FromMS > 0 {
						terms = append(terms, fmt.Sprintf("meta time >= %d", (r.FromMS+999)/1000))
					}
					if r.UntilMS > 0 {
						terms = append(terms, fmt.Sprintf("meta time < %d", r.UntilMS/1000))
					}
					variants := []string{""}
					if m.AnyPort > 0 {
						variants = []string{fmt.Sprintf("%s sport %d", proto, m.AnyPort), fmt.Sprintf("%s dport %d", proto, m.AnyPort)}
					}
					extras := proc
					// Input NEW is before socket lookup; inbound process uses the listen port.
					if reply || dir == "in" && !reply && (m.LocalPort > 0 || m.AnyPort > 0) {
						extras = []string{""}
					}
					for _, extra := range extras {
						for _, port := range variants {
							line := strings.Join(terms, " ")
							if port != "" {
								line += " " + port
							}
							if extra != "" {
								line += " " + extra
							}
							if r.Once {
								line += " add @" + onceSetName(r.ID) + " { ct id }"
							}
							verdict := "accept"
							if r.Action == "deny" || r.Action == "alert" {
								verdict = fmt.Sprintf("log group 100 prefix %q snaplen 256 queue-threshold 1 drop", "nm:drop:"+r.Action+":"+r.ID)
							}
							add(ch, line+" "+verdict)
						}
					}
				}
			}
		}
	}
	return nil
}
func preciseBlock(b Desired) bool {
	return b.Port != 0 || b.LocalPort != 0 || b.Protocol != "" && b.Protocol != "any" || b.Direction != "" && b.Direction != "both" && b.Direction != "any"
}
func banRule(b Desired, now time.Time) policy.Rule {
	expiry := b.ExpiresAtMS
	if expiry == 0 && b.Timeout > 0 {
		expiry = now.Add(b.Timeout).UnixMilli()
	}
	var networks []string
	if b.IP.IsValid() {
		ip := b.IP.Unmap()
		networks = []string{fmt.Sprintf("%s/%d", ip, ip.BitLen())}
	}
	return policy.Rule{ID: "ban:" + b.BlockID, Enabled: true, Action: "deny", UntilMS: expiry, Match: policy.Match{Networks: networks, Direction: b.Direction, Protocol: b.Protocol, LocalPort: b.LocalPort, RemotePort: b.Port}}
}
