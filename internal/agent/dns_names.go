package agent

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"netmonitor/internal/netipx"
	pol "netmonitor/internal/policy"
	"netmonitor/internal/protocol"
)

// lookupHostIPs resolves a rule name on the agent. Tests replace it.
var lookupHostIPs = func(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

const (
	nameRefresh       = 5 * time.Second
	nameLookupTimeout = 1200 * time.Millisecond
)

type resolvedName struct {
	at       time.Time
	prefixes []string
	reported map[string]bool
	pending  map[string]protocol.DNSPayload
}

func normalizeDNSName(raw string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
}

func uniqueDNSNames(rules []pol.Rule) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		for _, raw := range r.Match.Names {
			name := normalizeDNSName(raw)
			if name == "" || strings.Contains(name, "*") || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func usableNameIPs(ips []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, ip := range ips {
		if netipx.UsableNameIP(ip) {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

func prefixOf(ip netip.Addr) string {
	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(ip, bits).String()
}

// attachResolved adds every current address of a rule's DNS name to the
// firewall match and reports addresses the monitor has not been told yet.
func (a *Agent) attachResolved(rules []pol.Rule) ([]pol.Rule, []protocol.DNSPayload) {
	names := uniqueDNSNames(rules)
	now := time.Now()
	var stale []string
	a.nameMu.Lock()
	for _, name := range names {
		c := a.resolved[name]
		if c.at.IsZero() || now.Sub(c.at) >= nameRefresh {
			stale = append(stale, name)
		}
	}
	// Oldest attempts go first, so slow names cannot starve later names even
	// when every entry is stale again by the next policy poll.
	slices.SortStableFunc(stale, func(x, y string) int {
		return a.resolved[x].at.Compare(a.resolved[y].at)
	})
	a.nameMu.Unlock()
	started := time.Now()
	found := map[string][]netip.Addr{}
	tried := map[string]time.Time{}
	for _, name := range stale {
		if time.Since(started) >= nameLookupTimeout {
			break
		}
		// Each attempt has its own deadline; the next name gets a full attempt.
		ctx, cancel := context.WithTimeout(context.Background(), nameLookupTimeout)
		ips, err := lookupHostIPs(ctx, name)
		cancel()
		tried[name] = time.Now()
		if err == nil {
			found[name] = usableNameIPs(ips)
		}
	}
	a.nameMu.Lock()
	defer a.nameMu.Unlock()
	if a.resolved == nil {
		a.resolved = map[string]resolvedName{}
	}
	for _, name := range names {
		c := a.resolved[name]
		if c.reported == nil {
			c.reported = map[string]bool{}
		}
		if at, ok := tried[name]; ok {
			c.at = at
		}
		if clean := found[name]; len(clean) > 0 {
			c.prefixes = nil
			for _, ip := range clean {
				c.prefixes = append(c.prefixes, prefixOf(ip))
				address := ip.String()
				if c.reported[address] {
					continue
				}
				if c.pending == nil {
					c.pending = map[string]protocol.DNSPayload{}
				}
				kind := "a"
				if ip.Is6() {
					kind = "aaaa"
				}
				c.pending[address] = protocol.DNSPayload{Name: name, IP: address, Kind: kind}
			}
			// Resolvers rotate the order; a new order alone must not reload nft.
			slices.Sort(c.prefixes)
			c.prefixes = slices.Compact(c.prefixes)
		}
		a.resolved[name] = c
	}
	// Retry failed outbox inserts independently of DNS results, including names
	// removed from the current policy. Enqueue success hands delivery to outbox.
	var reports []protocol.DNSPayload
	for _, c := range a.resolved {
		for address, rec := range c.pending {
			reports = append(reports, rec)
			c.reported[address] = true
			delete(c.pending, address)
		}
	}
	slices.SortFunc(reports, func(x, y protocol.DNSPayload) int {
		if cmp := strings.Compare(x.Name, y.Name); cmp != 0 {
			return cmp
		}
		return strings.Compare(x.IP, y.IP)
	})
	out := append([]pol.Rule(nil), rules...)
	for i := range out {
		if len(out[i].Match.Names) > 0 && out[i].Match.Networks == nil {
			// An unresolved name matches no address; nil would mean any address.
			out[i].Match.Networks = []string{}
		}
		var extra []string
		for _, raw := range out[i].Match.Names {
			name := normalizeDNSName(raw)
			if name == "" || strings.Contains(name, "*") {
				continue
			}
			extra = append(extra, a.resolved[name].prefixes...)
		}
		out[i].Match.Networks = pol.MergeNetworks(out[i].Match.Networks, extra)
	}
	return out, reports
}

func (a *Agent) forgetReported(rec protocol.DNSPayload) {
	a.nameMu.Lock()
	defer a.nameMu.Unlock()
	name := normalizeDNSName(rec.Name)
	c, ok := a.resolved[name]
	if !ok || c.reported == nil {
		return
	}
	delete(c.reported, rec.IP)
	if c.pending == nil {
		c.pending = map[string]protocol.DNSPayload{}
	}
	c.pending[rec.IP] = rec
	a.resolved[name] = c
}
