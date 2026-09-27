package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/policy"
)

var starterRules = []struct {
	Chip string
	IDs  []string
}{
	{Chip: "ssh", IDs: []string{"default-ssh"}},
	{Chip: "dns", IDs: []string{"default-dns-udp", "default-dns-tcp"}},
	{Chip: "ntp", IDs: []string{"default-ntp"}},
	{Chip: "ubuntu", IDs: []string{"default-ubuntu"}},
}

func starterState(db policyReader) map[string]bool {
	out := map[string]bool{"dns": false, "ntp": false, "monitor": true, "ssh": false, "ubuntu": false}
	rs, err := readPolicyRules(db)
	if err != nil {
		return out
	}
	enabled := map[string]bool{}
	for _, r := range rs {
		enabled[r.ID] = r.Enabled
	}
	for _, s := range starterRules {
		on := true
		for _, id := range s.IDs {
			if !enabled[id] {
				on = false
				break
			}
		}
		out[s.Chip] = on
	}
	return out
}

func applyStarter(tx *sql.Tx, starter map[string]bool) error {
	if starter == nil {
		return nil
	}
	rs, err := readPolicyRules(tx)
	if err != nil {
		return err
	}
	byID := map[string]policy.Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	for _, s := range starterRules {
		on, ok := starter[s.Chip]
		if !ok {
			continue
		}
		for _, id := range s.IDs {
			r, exists := byID[id]
			if !exists || r.Enabled == on {
				continue
			}
			r.Enabled = on
			r.Version++
			raw, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err = tx.Exec("UPDATE policy_rules SET version=?,payload=? WHERE rule_id=?", r.Version, string(raw), id); err != nil {
				return err
			}
		}
	}
	if starter["monitor"] == false {
		return fmt.Errorf("адрес монитора остаётся в защите")
	}
	return nil
}
