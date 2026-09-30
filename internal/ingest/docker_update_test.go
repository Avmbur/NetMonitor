package ingest_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
)

func TestDockerFlowReclassificationClearsHostProcess(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Update(func(tx *sql.Tx) error {
		if _, e := tx.Exec("INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h','test',1,1)"); e != nil {
			return e
		}
		_, e := tx.Exec("INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	port := 8080
	uid := 0
	p := protocol.FlowPayload{FlowUID: "flow", BootID: "boot", IPVersion: 4, Protocol: "tcp", Direction: "unknown", Origin: "host",
		OrigSrcIP: "172.17.0.2", OrigDstIP: "203.0.113.50", LocalIP: "172.17.0.2", RemoteIP: "203.0.113.50", RemotePort: &port,
		FirstSeenMS: 1, LastSeenMS: 1, ProcComm: "docker-proxy", ProcPath: "/usr/bin/docker-proxy", ProcCgroup: "/system.slice/docker.service", ProcUID: &uid}
	apply := func(seq int64) {
		t.Helper()
		raw, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		if e = st.Update(func(tx *sql.Tx) error {
			r := ingest.ApplyBatch(tx, ingest.Agent{ID: "a", HostID: "h", Trust: "trusted"}, []protocol.Event{{EventID: fmt.Sprint(seq), Seq: seq, Kind: "flow", ObservedAtMS: seq, Payload: raw}}, seq)
			if r.Fatal != nil {
				return r.Fatal
			}
			if r.Err != "" {
				return fmt.Errorf("%s", r.Err)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	apply(1)
	p.Direction, p.Origin = "out", "docker"
	p.ProcComm, p.ProcPath, p.ProcCgroup, p.ProcUID = "", "", "", nil
	p.LastSeenMS = 2
	apply(2)
	var direction, origin string
	var fields int
	if err = st.DB.QueryRow("SELECT direction,origin,(proc_comm IS NOT NULL)+(proc_path IS NOT NULL)+(proc_cgroup IS NOT NULL)+(proc_uid IS NOT NULL) FROM flows WHERE flow_uid='flow'").Scan(&direction, &origin, &fields); err != nil {
		t.Fatal(err)
	}
	if direction != "out" || origin != "docker" || fields != 0 {
		t.Fatalf("direction=%s origin=%s process fields=%d", direction, origin, fields)
	}
	p.Container = "pub"
	p.LastSeenMS = 3
	apply(3)
	var name string
	if err = st.DB.QueryRow("SELECT container FROM flows WHERE flow_uid='flow'").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "pub" {
		t.Fatal(name)
	}
}
