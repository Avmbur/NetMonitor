//go:build linux

package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Mirror only stateless predicates. Never duplicate limits, quotas, NAT, updates,
// maps with verdicts or other state-changing statements.
func ObserveForeignFirewall() error {
	raw, e := exec.Command("nft", "-j", "list", "ruleset").Output()
	if e != nil {
		return e
	}
	var doc struct {
		NFT []map[string]any `json:"nftables"`
	}
	if e = json.Unmarshal(raw, &doc); e != nil {
		return e
	}
	existing := map[string]map[string]any{}
	wanted := map[string]map[string]any{}
	for _, o := range doc.NFT {

		r, ok := o["rule"].(map[string]any)
		if !ok {
			continue
		}
		comment, _ := r["comment"].(string)
		if strings.HasPrefix(comment, "nm-observe:") {
			existing[comment] = r
			continue
		}
		if r["table"] == "netmon" || r["table"] == "netmon_collect" || r["chain"] == "NM_IN" || r["chain"] == "NM_OUT" {
			continue
		}
		ex, ok := r["expr"].([]any)
		if !ok {
			continue
		}
		verdict := ""
		safe := true
		var matches []any
		for _, item := range ex {
			m, ok := item.(map[string]any)
			if !ok {
				safe = false
				break
			}
			for k := range m {
				switch k {
				case "match":
					b, _ := json.Marshal(m)
					if bytes.Contains(b, []byte("numgen")) || bytes.Contains(b, []byte("jhash")) {
						safe = false
					}
					matches = append(matches, m)
				case "drop", "reject":
					verdict = k
				case "counter", "log":
				default:
					safe = false
				}
			}
		}
		if !safe || verdict == "" {
			continue
		}
		hash := sha256.Sum256(mustJSON(ex))
		tag := fmt.Sprintf("nm-observe:%v:%v:%v:%v:%x", r["family"], r["table"], r["chain"], r["handle"], hash[:4])
		matches = append(matches, map[string]any{"log": map[string]any{"group": NFLogGroup, "prefix": "nm:" + verdict + ":foreign", "snaplen": 256, "queue-threshold": 1}})
		wanted[tag] = map[string]any{"family": r["family"], "table": r["table"], "chain": r["chain"], "handle": r["handle"], "comment": tag, "expr": matches}
	}
	var commands []any
	for tag, r := range existing {
		if _, ok := wanted[tag]; !ok {
			commands = append(commands, map[string]any{"delete": map[string]any{"rule": map[string]any{"family": r["family"], "table": r["table"], "chain": r["chain"], "handle": r["handle"]}}})
		}
	}
	for tag, r := range wanted {
		if _, ok := existing[tag]; !ok {
			op := "insert"
			if _, has := r["handle"]; !has {
				op = "add"
			}
			commands = append(commands, map[string]any{op: map[string]any{"rule": r}})
		}
	}
	if len(commands) == 0 {
		return nil
	}
	cmd := exec.Command("nft", "-j", "-f", "-")
	cmd.Stdin = bytes.NewReader(mustJSON(map[string]any{"nftables": commands}))
	if b, e := cmd.CombinedOutput(); e != nil {
		return fmt.Errorf("NFLOG observation: %w: %s", e, b)
	}
	return nil
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
