package collect

import (
	"sync"
)

// MemEvent — событие снимка, ещё без номера. Номер ставит агент.
type MemEvent struct {
	Kind    string
	Pri     int
	Payload any
	Now     int64
}

// Mem хранит оперативные checkpoints и события прохода в памяти.
type Mem struct {
	mu           sync.Mutex
	cp           map[string]checkpoint
	ev           []MemEvent
	undo         map[string]previousCheckpoint
	beforeEvents []MemEvent
}

type previousCheckpoint struct {
	value  checkpoint
	exists bool
}

func NewMem() *Mem {
	return &Mem{cp: map[string]checkpoint{}}
}

// Begin/Commit/Rollback bracket one collector pass and queue acceptance.
// The owner serializes collection with queue publication. Only touched checkpoints are saved.
func (m *Mem) Begin() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.undo = make(map[string]previousCheckpoint)
	m.beforeEvents = append([]MemEvent(nil), m.ev...)
}

func (m *Mem) Commit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.undo, m.beforeEvents = nil, nil
}

func (m *Mem) Rollback() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, old := range m.undo {
		if old.exists {
			m.cp[key] = old.value
		} else {
			delete(m.cp, key)
		}
	}
	m.ev = m.beforeEvents
	m.undo, m.beforeEvents = nil, nil
}

func (m *Mem) rememberCheckpoint(key string) {
	if m.undo == nil {
		return
	}
	if _, ok := m.undo[key]; !ok {
		c, exists := m.cp[key]
		m.undo[key] = previousCheckpoint{c, exists}
	}
}

func (m *Mem) ApplyDump(entries []Entry, opt DumpOpts) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return applyDump(m, entries, opt)
}

func (m *Mem) ApplyEvent(e Entry, kind string, opt DumpOpts) error {
	if Skip(e, opt.Monitor, opt.MonitorPort) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return observe(m, e, kind, opt)
}

func (m *Mem) Take() []MemEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	ev := m.ev
	m.ev = nil
	return ev
}

func (m *Mem) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cp) == 0
}

func (m *Mem) loadCheckpoint(key string) (checkpoint, bool, error) {
	c, ok := m.cp[key]
	return c, ok, nil
}

func (m *Mem) saveCheckpoint(key string, c checkpoint) error {
	if m.cp == nil {
		m.cp = map[string]checkpoint{}
	}
	m.rememberCheckpoint(key)
	m.cp[key] = c
	return nil
}

func (m *Mem) checkpoints() (map[string]checkpoint, error) {
	out := make(map[string]checkpoint, len(m.cp))
	for k, c := range m.cp {
		out[k] = c
	}
	return out, nil
}

func (m *Mem) deleteStaleCheckpoints(beforeMono int64, bootID string) error {
	for key, c := range m.cp {
		if c.Flow.EndedAtMS != nil && c.SeenMono < beforeMono || c.Flow.BootID != bootID {
			m.rememberCheckpoint(key)
			delete(m.cp, key)
		}
	}
	return nil
}

func (m *Mem) enqueue(kind string, pri int, payload any, now int64) error {
	m.ev = append(m.ev, MemEvent{Kind: kind, Pri: pri, Payload: payload, Now: now})
	return nil
}
