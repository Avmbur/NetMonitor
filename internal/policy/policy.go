// Package policy is the canonical network policy shared by monitor and agent.
package policy

import (
	"fmt"
	"net/netip"
	"sort"
)

type Match struct {
	Direction  string    `json:"direction"`
	Protocol   string    `json:"protocol"`
	Networks   []string  `json:"networks"`
	LocalPort  int       `json:"local_port,omitempty"`
	RemotePort int       `json:"remote_port,omitempty"`
	AnyPort    int       `json:"any_port,omitempty"`
	Process    string    `json:"process,omitempty"`
	Cgroup     string    `json:"cgroup,omitempty"`
	UID        *int      `json:"uid,omitempty"`
	Bindings   []Binding `json:"bindings,omitempty"`
	Names      []string  `json:"names,omitempty"`
	// OnDemand — имена, адреса которых служба NetMonitor сама вписывает в фильтр
	// перед соединением, на ограниченный срок. Правило пускает только их (и
	// Networks, если заданы). Агент, не знающий поля, видит nil — любой адрес.
	OnDemand []string `json:"on_demand,omitempty"`
}
type Rule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       int64    `json:"version"`
	Enabled       bool     `json:"enabled"`
	Order         int      `json:"order"`
	Action        string   `json:"action"`
	Except        []string `json:"except,omitempty"`
	Hosts         []string `json:"hosts"` // nil means all; API rejects an explicitly empty selection.
	GroupID       string   `json:"group_id,omitempty"`
	Match         Match    `json:"match"`
	FromMS        int64    `json:"from_ms,omitempty"`
	UntilMS       int64    `json:"until_ms,omitempty"`
	Once          bool     `json:"once,omitempty"`
	OnceUsed      bool     `json:"once_used,omitempty"`
	OnceUsedHosts []string `json:"once_used_hosts,omitempty"`
}
type Contact struct {
	Direction, Protocol, RemoteIP, Process, Cgroup, Host string
	LocalPort, RemotePort                                int
	UID                                                  *int
}
type Decision struct{ Action, ID string }

func (r Rule) Active(now int64) bool {
	return r.Enabled && (r.FromMS == 0 || now >= r.FromMS) && (r.UntilMS == 0 || now < r.UntilMS)
}
func (r Rule) OnHost(host string) bool {
	for _, h := range r.Except {
		if h == host {
			return false
		}
	}
	if r.Hosts == nil {
		return true
	}
	for _, h := range r.Hosts {
		if h == host {
			return true
		}
	}
	return false
}
func (m Match) Matches(c Contact) bool {
	if m.Direction != "" && m.Direction != "any" && m.Direction != "both" && m.Direction != c.Direction {
		return false
	}
	if m.Protocol != "" && m.Protocol != "any" && m.Protocol != c.Protocol {
		return false
	}
	if m.LocalPort > 0 && m.LocalPort != c.LocalPort || m.RemotePort > 0 && m.RemotePort != c.RemotePort || m.AnyPort > 0 && m.AnyPort != c.LocalPort && m.AnyPort != c.RemotePort {
		return false
	}
	if m.Bound() {
		hit := false
		if len(m.Bindings) > 0 {
			for _, b := range m.Bindings {
				if b.matches(c) {
					hit = true
					break
				}
			}
		} else {
			legacy := Binding{Cgroup: m.Cgroup, Path: m.Process, UID: m.UID}
			hit = legacy.matches(c)
		}
		if !hit {
			return false
		}
	}
	if m.Networks == nil {
		// Адреса «по запросу» живут только в фильтре агента: здесь их нет.
		return len(m.OnDemand) == 0
	}
	ip, err := netip.ParseAddr(c.RemoteIP)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, n := range m.Networks {
		p, err := netip.ParsePrefix(n)
		if err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
func Validate(r Rule) error {
	if r.Action != "allow" && r.Action != "deny" && r.Action != "observe" && r.Action != "alert" {
		return fmt.Errorf("unknown action")
	}
	m := r.Match
	if m.Direction != "" && m.Direction != "in" && m.Direction != "out" && m.Direction != "both" && m.Direction != "any" {
		return fmt.Errorf("invalid direction")
	}
	switch m.Protocol {
	case "", "any", "tcp", "udp", "icmp", "icmpv6":
	default:
		return fmt.Errorf("invalid protocol")
	}
	for _, p := range []int{m.LocalPort, m.RemotePort, m.AnyPort} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("invalid port")
		}
	}
	// Порт при любом протоколе — это tcp и udp сразу: у icmp портов нет.
	if (m.LocalPort > 0 || m.RemotePort > 0 || m.AnyPort > 0) && (m.Protocol == "icmp" || m.Protocol == "icmpv6") {
		return fmt.Errorf("a port requires tcp, udp or any protocol")
	}
	for _, n := range m.Networks {
		p, e := netip.ParsePrefix(n)
		if e != nil || p.Addr().Is4In6() || p != p.Masked() {
			return fmt.Errorf("invalid canonical network %q", n)
		}
	}
	if r.FromMS < 0 || r.UntilMS < 0 || r.UntilMS > 0 && r.FromMS >= r.UntilMS {
		return fmt.Errorf("invalid rule lifetime")
	}
	if r.Hosts != nil && len(r.Hosts) == 0 {
		return fmt.Errorf("empty server selection")
	}
	return nil
}

// Unsupported precision is rejected, never broadened to a whole address/uid.
func Executable(r Rule) error {
	if err := Validate(r); err != nil {
		return err
	}
	if r.Once && r.Action != "allow" {
		return fmt.Errorf("однократность только у разрешающего правила")
	}
	if r.Once && !r.hasMatchCondition() {
		return fmt.Errorf("однократность без условий не сохраняется")
	}
	if len(r.Match.Bindings) > 0 {
		for _, b := range r.Match.Bindings {
			if err := b.Enforceable(); err != nil {
				return err
			}
		}
		return nil
	}
	if r.Match.Cgroup != "" || r.Match.UID != nil {
		return (Binding{Cgroup: r.Match.Cgroup, Path: r.Match.Process, UID: r.Match.UID}).Enforceable()
	}
	if r.Match.Process != "" {
		b, err := ParseIdentity(r.Match.Process, "", "")
		if err != nil {
			return err
		}
		return b.Enforceable()
	}
	return nil
}
func Ordered(rs []Rule) []Rule {
	out := append([]Rule(nil), rs...)
	weight := func(a string) int {
		if a == "deny" {
			return 0
		}
		if a == "alert" {
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return weight(out[i].Action) < weight(out[j].Action)
	})
	return out
}
func Evaluate(rs []Rule, host string, c Contact, now int64) (Decision, bool) {
	c.Host = host
	for _, r := range Ordered(rs) {
		if r.Active(now) && !r.SpentOn(host) && r.OnHost(host) && r.Match.Matches(c) {
			return Decision{r.Action, r.ID}, true
		}
	}
	return Decision{}, false
}

// MergeNetworks adds addresses. An empty addition keeps nil as "any address";
// a rule by name must start from an empty list, not nil.
func MergeNetworks(existing, more []string) []string {
	if len(more) == 0 {
		return existing
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(more))
	for _, n := range existing {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range more {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) == 0 {
		return existing
	}
	return out
}

// IntersectNetworks preserves nil=any and []=none. Overlapping CIDRs intersect
// at their more specific prefix, so a group cannot widen an explicit address.
func IntersectNetworks(a, b []string) []string {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := []string{}
	seen := map[string]bool{}
	for _, x := range a {
		px, ex := netip.ParsePrefix(x)
		if ex != nil {
			continue
		}
		for _, y := range b {
			py, ey := netip.ParsePrefix(y)
			if ey != nil || px.Addr().BitLen() != py.Addr().BitLen() {
				continue
			}
			var n string
			if px.Contains(py.Addr()) && px.Bits() <= py.Bits() {
				n = py.String()
			} else if py.Contains(px.Addr()) && py.Bits() <= px.Bits() {
				n = px.String()
			}
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}
