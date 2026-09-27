package policy

import "strconv"

// StarterSSH is the starter rule that keeps SSH open so a server is not locked out.
const StarterSSH = "default-ssh"

// ExpandStarterSSH adds a copy of the starter SSH rule for every sshd port other
// than 22. The rule itself stays on 22; a rule already moved off 22 by hand is
// left alone. Monitor and agent run the same expansion, so the agent opens the
// ports it sees locally before the monitor has its report.
func ExpandStarterSSH(rules []Rule, ports []int) []Rule {
	base := -1
	have := map[string]bool{}
	for i, r := range rules {
		have[r.ID] = true
		if r.ID == StarterSSH && r.Match.LocalPort == 22 {
			base = i
		}
	}
	if base < 0 {
		return rules
	}
	var extra []Rule
	for _, p := range ports {
		id := StarterSSH + "-" + strconv.Itoa(p)
		if p == 22 || p < 1 || p > 65535 || have[id] {
			continue
		}
		have[id] = true
		r := rules[base]
		r.ID = id
		r.Match.LocalPort = p
		extra = append(extra, r)
	}
	if len(extra) == 0 {
		return rules
	}
	out := make([]Rule, 0, len(rules)+len(extra))
	out = append(out, rules[:base+1]...)
	out = append(out, extra...)
	return append(out, rules[base+1:]...)
}
