package fw

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"
)

func (c *Controller) nftState() (string, map[string]bool, error) {
	raw, err := c.execute("", "nft", "-j", "list", "table", "inet", "netmon")
	if err != nil {
		return "", nil, err
	}
	var doc struct {
		NFT []map[string]any `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		return "", nil, err
	}
	var items []any
	actual := map[string]bool{}
	for _, entry := range doc.NFT {
		if _, ok := entry["metainfo"]; ok {
			continue
		}
		if set, ok := entry["set"].(map[string]any); ok {
			name, _ := set["name"].(string)
			if name == "ban4" || name == "ban6" {
				if elems, ok := set["elem"].([]any); ok {
					for _, v := range elems {
						if m, ok := v.(map[string]any); ok {
							if e, ok := m["elem"].(map[string]any); ok {
								v = e["val"]
							}
						}
						ip, ok := v.(string)
						if !ok {
							return "", nil, fmt.Errorf("unexpected ban element")
						}
						actual[ip] = true
					}
				}
			}
			if strings.HasPrefix(name, "learn") || name == "ban4" || name == "ban6" {
				delete(set, "elem")
			}
			// Elements of static sets are unordered; rule order remains significant.
			if elems, ok := set["elem"].([]any); ok {
				sort.Slice(elems, func(i, j int) bool {
					a, _ := json.Marshal(elems[i])
					b, _ := json.Marshal(elems[j])
					return string(a) < string(b)
				})
			}
		}
		stripHandles(entry)
		items = append(items, entry)
	}
	if len(items) == 0 {
		return "", nil, fmt.Errorf("empty nft state")
	}
	out, err := json.Marshal(items)
	return string(out), actual, err
}
func stripHandles(v any) {
	switch m := v.(type) {
	case map[string]any:
		delete(m, "handle")
		for _, x := range m {
			stripHandles(x)
		}
	case []any:
		for _, x := range m {
			stripHandles(x)
		}
	}
}
func (c *Controller) nftAlive() bool {
	if c.signature == "" {
		return false
	}
	sig, actual, err := c.nftState()
	if err != nil || sig != c.signature {
		return false
	}
	want := map[string]bool{}
	now := time.Now().UnixMilli()
	for _, b := range c.lastPolicy.Blocks {
		if preciseBlock(b) {
			continue
		}
		if b.ExpiresAtMS == 0 || b.ExpiresAtMS > now {
			want[b.IP.Unmap().String()] = true
		}
	}
	return reflect.DeepEqual(want, actual)
}
func clonePolicy(p Policy) Policy {
	raw, _ := json.Marshal(p)
	_ = json.Unmarshal(raw, &p)
	p.Blocks = append([]Desired(nil), p.Blocks...)
	p.Never = append([]netip.Prefix(nil), p.Never...)
	p.BlockNets = append([]netip.Prefix(nil), p.BlockNets...)
	p.AllowNets = append([]netip.Prefix(nil), p.AllowNets...)
	now := time.Now()
	for i := range p.Blocks {
		b := &p.Blocks[i]
		if b.ExpiresAtMS == 0 && b.Timeout > 0 {
			b.ExpiresAtMS = now.Add(b.Timeout).UnixMilli()
			b.Timeout = 0
		}
	}
	return p
}
