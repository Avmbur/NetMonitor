package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/store"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
)

// Stream registration and publication share agentStateMu with deletion.
// A new process replaces the previous live state even if the OS did not reboot.
type serviceStream struct {
	instance string
	lanes    map[string]int64
}

func (s *Server) registerStream(agentID, instance string) (bool, error) {
	if instance == "" {
		return false, nil
	}
	s.agentStateMu.Lock()
	defer s.agentStateMu.Unlock()
	var trust string
	if err := s.st.DB.QueryRow("SELECT trust_state FROM agents WHERE agent_id=?", agentID).Scan(&trust); err != nil {
		return false, err
	}
	if trust == "revoked" {
		return false, fmt.Errorf("agent revoked")
	}
	if s.streams == nil {
		s.streams = map[string]*serviceStream{}
	}
	if old := s.streams[agentID]; old != nil && old.instance == instance {
		return false, nil
	}
	s.streams[agentID] = &serviceStream{instance: instance, lanes: map[string]int64{}}
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if s.live.instances == nil {
		s.live.instances = map[string]string{}
	}
	s.live.instances[agentID] = instance
	for uid, f := range s.live.open {
		if f.agentID == agentID {
			delete(s.live.open, uid)
		}
	}
	return true, nil
}

// Only call after the database commit. Failed batches cannot change the UI pulse.
func (s *Server) publishPulse(j *batchJob) {
	for _, ev := range j.applied {
		if ev.Kind == "dns" {
			s.noteLiveDNS(j.ag.HostID, ev, j.now)
		}
		if ev.Kind != "health" {
			continue
		}
		var p protocol.HealthPayload
		if json.Unmarshal(ev.Payload, &p) != nil {
			continue
		}
		switch p.Kind {
		case "conntrack_gap", "dump_error", "nflog_error", "collector_setup":
			s.pulseMu.Lock()
			if s.collectFault == nil {
				s.collectFault = map[string]string{}
			}
			note := p.Kind
			if p.Note != "" {
				note += ": " + p.Note
			}
			s.collectFault[j.ag.HostID] = note + " " + time.UnixMilli(ev.ObservedAtMS).Format("02.01 15:04:05")
			s.pulseMu.Unlock()
		}
		if !freshAlive(j.ag.DeliveryLane, ev, p, j.now) {
			continue
		}
		s.pulseMu.Lock()
		if s.hostSeen == nil {
			s.hostSeen = map[string]int64{}
		}
		if s.hostInv == nil {
			s.hostInv = map[string]protocol.HealthPayload{}
		}
		s.hostSeen[j.ag.HostID] = j.now
		s.hostInv[j.ag.HostID] = p
		s.pulseMu.Unlock()
	}
}

func freshAlive(lane string, ev protocol.Event, p protocol.HealthPayload, now int64) bool {
	return (p.Kind == "" || p.Kind == "alive") && (lane == "heartbeat" || lane != "history" && now-ev.ObservedAtMS < 30000 && ev.ObservedAtMS-now < 30000)
}

// Questions are durable service decisions. Their delivery receipt must survive a
// monitor restart too; telemetry receipts remain exclusively in RAM.
func questionReceipt(tx *sql.Tx, agentID string, ev protocol.Event, now int64) (bool, error) {
	floor, err := questionFloor(tx, agentID)
	if err != nil {
		return false, err
	}
	if ev.Seq < floor {
		return false, nil
	}
	var owner, sha string
	err = tx.QueryRow("SELECT agent_id,payload_sha256 FROM ingest_events WHERE event_id=?", ev.EventID).Scan(&owner, &sha)
	if err == nil {
		if owner != agentID || sha != idgen.SHA256Hex(ev.Payload) {
			return false, fmt.Errorf("question owner mismatch")
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	return true, nil
}

func telemetryKind(kind string) bool {
	switch kind {
	case "flow", "sample", "firewall", "health", "ssh", "scan", "dns":
		return true
	}
	return false
}

func recordQuestionReceipt(tx *sql.Tx, agentID string, ev protocol.Event, now int64) error {
	_, err := tx.Exec("INSERT INTO ingest_events(event_id,agent_id,seq,kind,observed_at_ms,received_at_ms,payload_sha256) VALUES(?,?,?,?,?,?,?)", ev.EventID, agentID, ev.Seq, ev.Kind, ev.ObservedAtMS, now, idgen.SHA256Hex(ev.Payload))
	return err
}

// The durable queue has its own sequence space; telemetry cannot advance it.
func questionFloor(tx *sql.Tx, agent string) (int64, error) {
	var raw string
	err := tx.QueryRow("SELECT v FROM settings WHERE k=?", "question_floor:"+agent).Scan(&raw)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(raw, 10, 64)
}

func (s *Server) confirmQuestions(tx *sql.Tx, agent string, floor int64) error {
	old, err := questionFloor(tx, agent)
	if err != nil || floor <= old {
		return err
	}
	if err = store.PutSetting(tx, "question_floor:"+agent, strconv.FormatInt(floor, 10)); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM ingest_events WHERE agent_id=? AND seq<?", agent, floor); err != nil {
		return err
	}
	store.OnFinish(tx, func(ok bool) {
		if !ok {
			return
		}
		s.qMu.Lock()
		defer s.qMu.Unlock()
		for key, seq := range s.qSeen {
			if strings.HasPrefix(key, agent+"\n") && seq < floor {
				delete(s.qSeen, key)
			}
		}
	})
	return nil
}
