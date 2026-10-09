package server

import (
	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"strings"
)

// Events awaiting publication only; no disk flush queue exists.
type stagedEvent struct {
	ag       ingest.Agent
	ev       protocol.Event
	received int64
}

func (s *Server) forgetAgentMemory(id string) {
	delete(s.streams, id)
	s.qMu.Lock()
	for key := range s.qSeen {
		if strings.HasPrefix(key, id+"\n") {
			delete(s.qSeen, key)
		}
	}
	s.qMu.Unlock()
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	delete(s.live.instances, id)
	for uid, f := range s.live.open {
		if f.agentID == id {
			delete(s.live.open, uid)
		}
	}
}
