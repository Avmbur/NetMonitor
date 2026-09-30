package server

import (
	"context"
	"database/sql"
	"net"
	"net/netip"
	"strings"
	"time"

	"netmonitor/internal/netipx"
	"netmonitor/internal/policy"
)

const nameResolveHost = "name-resolve"

// lookupNameIPs resolves a rule name on the monitor. Tests replace it.
var lookupNameIPs = func(name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

type seededAddr struct {
	name string
	ips  []netip.Addr
}

func resolveRuleNames(names []string) []seededAddr {
	var out []seededAddr
	seen := map[string]bool{}
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if name == "" || strings.Contains(name, "*") || seen[name] {
			continue
		}
		seen[name] = true
		ips, err := lookupNameIPs(name)
		if err != nil || len(ips) == 0 {
			continue
		}
		var clean []netip.Addr
		for _, ip := range ips {
			if netipx.UsableNameIP(ip) {
				clean = append(clean, ip.Unmap())
			}
		}
		if len(clean) == 0 {
			continue
		}
		out = append(out, seededAddr{name: name, ips: clean})
	}
	return out
}

func rememberResolved(tx *sql.Tx, hosts []string, seed []seededAddr, now int64) error {
	if len(seed) == 0 {
		return nil
	}
	if hosts == nil {
		var err error
		hosts, err = policyStrings(tx, `SELECT host_id FROM hosts`)
		if err != nil {
			return err
		}
	}
	if len(hosts) == 0 {
		hosts = []string{nameResolveHost}
	}
	for _, host := range hosts {
		for _, s := range seed {
			for _, ip := range s.ips {
				if _, err := tx.Exec(`
INSERT INTO dns_seen(host_id, name, ip_bin, ip, first_seen_ms, last_seen_ms)
VALUES(?,?,?,?,?,?)
ON CONFLICT(host_id, name, ip_bin) DO UPDATE SET last_seen_ms=excluded.last_seen_ms`,
					host, s.name, netipx.Bin16(ip), netipx.Canonical(ip), now, now); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func expandRuleNames(db policyReader, r policy.Rule) (policy.Rule, error) {
	if len(r.Match.Names) == 0 {
		return r, nil
	}
	if r.Match.Networks == nil {
		// An unresolved name matches no address; nil would mean any address.
		r.Match.Networks = []string{}
	}
	var extra []string
	for _, n := range r.Match.Names {
		ips, err := resolvePattern(db, n)
		if err != nil {
			return r, err
		}
		for _, ip := range ips {
			if p, ok := ipToPrefix(ip); ok {
				extra = append(extra, p)
			}
		}
	}
	r.Match.Networks = policy.MergeNetworks(r.Match.Networks, extra)
	return r, nil
}
