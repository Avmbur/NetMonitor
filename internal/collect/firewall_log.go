package collect

import (
	"fmt"
	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"strings"
	"time"
)

type fwWindow struct {
	Payload protocol.FirewallPayload
	Due     time.Time
	Last    time.Time
}
type FirewallLog struct{ windows map[string]*fwWindow }

func (f *FirewallLog) Observe(p protocol.FirewallPayload, now time.Time) []protocol.FirewallPayload {
	if f.windows == nil {
		f.windows = map[string]*fwWindow{}
	}
	key := fmt.Sprintf("%s/%s/%s/%s/%v/%v/%s", p.Direction, p.Protocol, p.LocalIP, p.RemoteIP, portValue(p.LocalPort), portValue(p.RemotePort), p.RuleTag)
	var out []protocol.FirewallPayload
	w := f.windows[key]
	if w != nil && !now.Before(w.Due) {
		if w.Payload.Hits > 0 {
			out = append(out, w.Payload)
		}
		delete(f.windows, key)
		w = nil
	}
	if w == nil {
		p.GroupID = idgen.NewV7()
		out = append(out, p)
		p.Hits = 0
		duration := 10 * time.Second
		if strings.Contains(p.RuleTag, ":ban") {
			duration = time.Minute
		}
		f.windows[key] = &fwWindow{p, now.Add(duration), now}
	} else {
		w.Payload.Hits++
		w.Last = now
	}
	return out
}
func (f *FirewallLog) Flush(now time.Time) []protocol.FirewallPayload {
	var out []protocol.FirewallPayload
	for key, w := range f.windows {
		if !now.Before(w.Due) {
			if w.Payload.Hits > 0 {
				out = append(out, w.Payload)
			}
			delete(f.windows, key)
		}
	}
	return out
}
func portValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
