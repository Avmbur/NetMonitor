package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/netip"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
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
ON CONFLICT(host_id, name, ip_bin) DO UPDATE SET
  first_seen_ms=MIN(dns_seen.first_seen_ms, excluded.first_seen_ms),
  last_seen_ms=MAX(dns_seen.last_seen_ms, excluded.last_seen_ms)`,
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
	found, err := resolvePatterns(db, r.Match.Names)
	if err != nil {
		return r, err
	}
	var extra []string
	for _, n := range r.Match.Names {
		for _, ip := range found[strings.ToLower(strings.TrimSpace(n))] {
			if p, ok := ipToPrefix(ip); ok {
				extra = append(extra, p)
			}
		}
	}
	r.Match.Networks = policy.MergeNetworks(r.Match.Networks, extra)
	return r, nil
}

type serviceName struct {
	name string
	at   int64
}

const liveNameLimit = 4096

func (s *Server) noteLiveDNS(host string, ev protocol.Event, now int64) {
	var p protocol.DNSPayload
	if json.Unmarshal(ev.Payload, &p) != nil || p.Name == "" || p.IP == "" {
		return
	}
	key := host + "\n" + canonIP(p.IP)
	s.nameMu.Lock()
	defer s.nameMu.Unlock()
	if s.liveNames == nil {
		s.liveNames = map[string]serviceName{}
	}
	if _, ok := s.liveNames[key]; !ok && len(s.liveNames) >= liveNameLimit {
		oldest := ""
		at := int64(1 << 62)
		for k, v := range s.liveNames {
			if v.at < at {
				oldest, at = k, v.at
			}
		}
		delete(s.liveNames, oldest)
	}
	s.liveNames[key] = serviceName{name: strings.ToLower(strings.TrimSuffix(p.Name, ".")), at: now}
}

func (s *Server) lookupDNS(db *checkedRead, host, ip, proto string, port int) string {
	{
		s.nameMu.Lock()
		v, ok := s.liveNames[host+"\n"+canonIP(ip)]
		s.nameMu.Unlock()
		if ok && store.NowMS()-v.at < 3600000 {
			return v.name
		}
	}
	return lookupDNS(db, host, ip, proto, port)
}
