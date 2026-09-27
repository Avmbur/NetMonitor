package collect

import (
	"net/netip"
	"netmonitor/internal/protocol"
	"sync"
	"time"
)

const (
	ScanWindow = 60 * time.Second
	ScanPorts  = 5
)

type scanKey struct {
	proto string
	ip    netip.Addr
	port  int
}

type Tracker struct {
	mu     sync.Mutex
	hits   map[scanKey]time.Time
	fired  map[netip.Addr]time.Time
	window time.Duration
	need   int
}

func NewTracker() *Tracker {
	return &Tracker{
		hits:   map[scanKey]time.Time{},
		fired:  map[netip.Addr]time.Time{},
		window: ScanWindow,
		need:   ScanPorts,
	}
}

type ScanHit struct {
	Attempts []protocol.ScanAttempt
	IP       netip.Addr
	Ports    []int
}

func (t *Tracker) SetNeed(n int) {
	if n > 0 {
		t.need = n
	}
}
func (t *Tracker) SetWindow(d time.Duration) {
	if d > 0 {
		t.window = d
	}
}

func (t *Tracker) Observe(e Entry, local []netip.Addr, now time.Time, skipPort int) *ScanHit {
	dir, _, remoteIP, lport, _ := Classify(e, local)
	if dir != "in" || lport == nil || *lport <= 0 {
		return nil
	}
	if skipPort > 0 && *lport == skipPort {
		return nil
	}
	rip, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return nil
	}
	rip = rip.Unmap()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc(now)
	if last, ok := t.fired[rip]; ok && now.Sub(last) < t.window {
		return nil
	}
	t.hits[scanKey{ip: rip, port: *lport, proto: e.Protocol}] = now
	ports := map[int]struct{}{}
	for k, ts := range t.hits {
		if k.ip == rip && now.Sub(ts) <= t.window {
			ports[k.port] = struct{}{}
		}
	}
	if len(ports) < t.need {
		return nil
	}
	t.fired[rip] = now
	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	var attempts []protocol.ScanAttempt
	for k, ts := range t.hits {
		if k.ip == rip && now.Sub(ts) <= t.window {
			attempts = append(attempts, protocol.ScanAttempt{Protocol: k.proto, Port: k.port})
		}
	}
	return &ScanHit{IP: rip, Ports: out, Attempts: attempts}
}

func (t *Tracker) gc(now time.Time) {
	for k, ts := range t.hits {
		if now.Sub(ts) > t.window {
			delete(t.hits, k)
		}
	}
	for ip, ts := range t.fired {
		if now.Sub(ts) > t.window {
			delete(t.fired, ip)
		}
	}
}
