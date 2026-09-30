package server

import (
	"database/sql"
	"encoding/json"
	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestDockerUIContactIdentity(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Update(func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h','test',1,1)"); e != nil {
			return e
		}
		if _, e := tx.Exec("INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)"); e != nil {
			return e
		}
		port := 8080
		flow := protocol.FlowPayload{FlowUID: "f", BootID: "b", IPVersion: 4, Protocol: "tcp", Direction: "in", Origin: "docker",
			OrigSrcIP: "203.0.113.50", OrigDstIP: "192.168.10.186", ReplySrcIP: "172.17.0.2", LocalIP: "192.168.10.186", RemoteIP: "203.0.113.50",
			LocalPort: &port, FirstSeenMS: 1, LastSeenMS: 1, State: "ESTABLISHED"}
		q := protocol.QuestionPayload{Direction: "in", Protocol: "tcp", LocalPort: 8080, RemotePort: 40000, RemoteIP: "203.0.113.50",
			DedupKey: "in|tcp|203.0.113.50|8080|||\u25a3172.17.0.2", Repeats: 1}
		for i, p := range []any{flow, q} {
			kind := "flow"
			if i == 1 {
				kind = "question"
			}
			raw, e := json.Marshal(p)
			if e != nil {
				return e
			}
			r := ingest.ApplyBatch(tx, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, []protocol.Event{{EventID: kind, Seq: int64(i + 1), Kind: kind, ObservedAtMS: 1, Payload: raw}}, 1)
			if r.Fatal != nil {
				return r.Fatal
			}
			if r.Err != "" {
				t.Fatal(r.Err)
			}
		}
		// Simulate metadata left by a previous collector. It must not be shown or used.
		_, e := tx.Exec("UPDATE flows SET proc_comm='docker-proxy',proc_path='/usr/bin/docker-proxy',proc_cgroup='/system.slice/docker.service'")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	db := &checkedRead{db: st.DB}
	s := &Server{st: st}
	qs := s.listQuestions(db, "", false)
	fs := readUIFlows(db, "", false, false)
	if db.err != nil {
		t.Fatal(db.err)
	}
	if len(qs) != 1 || len(fs) != 1 {
		t.Fatalf("questions=%d flows=%d", len(qs), len(fs))
	}
	if qs[0].ContainerIP != "172.17.0.2" || qs[0].Port != 8080 || qs[0].Proc != "\u2014" || qs[0].Path != "" {
		t.Fatalf("question: %+v", qs[0])
	}
	if fs[0].ContainerIP != "172.17.0.2" || fs[0].Port != 8080 || fs[0].Path != "" || fs[0].Proc == "docker-proxy" {
		t.Fatalf("flow: %+v", fs[0])
	}
}
