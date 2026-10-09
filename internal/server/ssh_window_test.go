package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"

	"encoding/json"

	"net/http"
	"net/http/httptest"

	"testing"

	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestSSHWindowExactBoundary(t *testing.T) {
	s := &Server{}
	job := &batchJob{}
	now := int64(1_700_000_000_000)
	ip := "203.0.113.9"
	s.ssh.add(job, sshHit{id: "edge", host: "h", ip: ip, at: now - sshWindowMS})
	s.ssh.add(job, sshHit{id: "in", host: "h", ip: ip, at: now - sshWindowMS + 1})
	s.ssh.add(job, sshHit{id: "edge", host: "h", ip: ip, at: now})
	s.ssh.add(job, sshHit{id: "other-host", host: "h2", ip: ip, at: now})
	s.ssh.add(job, sshHit{id: "other-ip", host: "h", ip: "203.0.113.10", at: now})
	if n := s.ssh.count("h", ip, now); n != 1 {
		t.Fatalf("boundary %d", n)
	}
	s.ssh.drop(job)
	if n := s.ssh.count("h", ip, now); n != 0 {
		t.Fatalf("rollback left %d", n)
	}
	wall := store.NowMS()
	s.ssh.add(job, sshHit{id: "live", host: "h", ip: ip, at: wall})
	s.ssh.keep(job)
	s.moveSSHHost("h", "moved")
	if s.ssh.count("h", ip, wall) != 0 || s.ssh.count("moved", ip, wall) != 1 {
		t.Fatal("rebind")
	}
}

func TestSSHWindowFifthAttempt(t *testing.T) {
	t.Run("batch", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.50"
		evs := sshBurst("batch", ip, 5, store.NowMS())
		mustSSH(t, s, cert, "", evs...)
		if sshBanCount(t, s) != 1 || countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
			t.Fatalf("bans=%d rows=%d window=%d", sshBanCount(t, s), countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
		}
		mustSSH(t, s, cert, "", evs...)
		if sshBanCount(t, s) != 1 || countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
			t.Fatal("replay after ban", sshBanCount(t, s), countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
		}
	})
	t.Run("boundary", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.51"
		mark := store.NowMS()
		var evs []protocol.Event
		evs = append(evs, sshEv("out", 1, mark, mark-sshWindowMS-30_000, ip))
		for i := 1; i <= 4; i++ {
			evs = append(evs, sshEv("in"+string(rune('0'+i)), int64(i+1), mark, mark-sshWindowMS+30_000, ip))
		}
		mustSSH(t, s, cert, "", evs...)
		if sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 4 {
			t.Fatalf("outside counted bans=%d window=%d", sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()))
		}
		mustSSH(t, s, cert, "", sshEv("fifth", 6, store.NowMS(), store.NowMS(), ip))
		if sshBanCount(t, s) != 1 {
			t.Fatal("fifth inside did not ban")
		}
	})
	t.Run("decoy", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.52"
		now := store.NowMS()
		first := sshEv("real-1", 1, now, 0, ip)
		mustSSH(t, s, cert, "", first)
		insertSSHRow(t, s, "decoy", ip, now)
		var more []protocol.Event
		for i := 2; i <= 4; i++ {
			more = append(more, sshEv("real-"+string(rune('0'+i)), int64(i), store.NowMS(), 0, ip))
		}
		mustSSH(t, s, cert, "", more...)
		if sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 4 || countTable(t, s, "ssh_failures") != 1 {
			t.Fatalf("decoy moved the ban bans=%d window=%d rows=%d", sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()), countTable(t, s, "ssh_failures"))
		}
		from, to := now-1000, store.NowMS()+1000
		got, err := s.repSSH(from, to, "")
		if err != nil {
			t.Fatal(err)
		}
		if sshLine(got, ip) == nil || sshLine(got, ip)[2] != "4" {
			t.Fatalf("old disk row entered current window: %v", got)
		}

	})
}

func TestSSHWindowPolicyKeepsAttempts(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.61"
		r := ruleRequest(t, s, `{"name":"SSH allow","kind":"allow","proto":"tcp","direction":"in","portSide":"local","port":22,"networks":["203.0.113.61/32"],"hosts":["h"]}`, 200)
		evs := sshBurst("allow", ip, 5, store.NowMS())
		mustSSH(t, s, cert, "", evs...)
		if sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
			t.Fatalf("allow bans=%d window=%d", sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()))
		}
		body, _ := json.Marshal(map[string]any{"id": r.ID, "version": r.Version, "enabled": false, "kind": "allow", "proto": "tcp", "direction": "in", "portSide": "local", "port": 22, "hosts": []string{"h"}})
		ruleRequest(t, s, string(body), 200)
		mustSSH(t, s, cert, "", sshEv("allow-6", 6, store.NowMS(), 0, ip))
		if sshBanCount(t, s) != 1 {
			t.Fatal("window lost the allowed attempts")
		}
	})
	t.Run("pause", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.62"
		if _, err := s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('host_control:h',?)`, `{"pause_from":0,"pause_until":4000000000000000}`); err != nil {
			t.Fatal(err)
		}
		mustSSH(t, s, cert, "", sshBurst("pause", ip, 5, store.NowMS())...)
		if sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
			t.Fatalf("pause bans=%d window=%d", sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()))
		}
		if _, err := s.st.DB.Exec(`UPDATE settings SET v='{"mode":"park"}' WHERE k='host_control:h'`); err != nil {
			t.Fatal(err)
		}
		mustSSH(t, s, cert, "", sshEv("pause-6", 6, store.NowMS(), 0, ip))
		if sshBanCount(t, s) != 1 {
			t.Fatal("paused attempts dropped out of the window")
		}
	})
	t.Run("history", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.63"
		mustSSH(t, s, cert, "history", sshBurst("hist", ip, 5, store.NowMS())...)
		if sshBanCount(t, s) != 0 || countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
			t.Fatalf("history bans=%d rows=%d window=%d", sshBanCount(t, s), countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
		}
		mustSSH(t, s, cert, "", sshEv("hist-live", 6, store.NowMS(), 0, ip))
		if sshBanCount(t, s) != 1 {
			t.Fatal("history attempts were not in the window")
		}
	})
	t.Run("never", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.64"
		if _, err := saveNever(s.st, "", ip, "test", "adm"); err != nil {
			t.Fatal(err)
		}
		mustSSH(t, s, cert, "", sshBurst("never", ip, 5, store.NowMS())...)
		if sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 || countTable(t, s, "ssh_failures") != 0 {
			t.Fatalf("never bans=%d window=%d rows=%d", sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()), countTable(t, s, "ssh_failures"))
		}
	})
	t.Run("replay before ban", func(t *testing.T) {
		s, cert := batchFixture(t)
		ip := "203.0.113.65"
		ev := sshEv("once", 1, store.NowMS(), 0, ip)
		mustSSH(t, s, cert, "", ev)
		mustSSH(t, s, cert, "", ev)
		if countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 1 || sshBanCount(t, s) != 0 {
			t.Fatal("replay counted twice", countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
		}
	})
}

func TestSSHWindowRollback(t *testing.T) {
	s, cert := batchFixture(t)
	ip := "203.0.113.70"
	if _, err := s.st.DB.Exec(`CREATE TRIGGER fail_ssh_ban BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	evs := sshBurst("roll", ip, 5, store.NowMS())
	code, _ := sendLane(t, s, cert, "", evs...)
	if code != 500 {
		t.Fatalf("rollback acked %d", code)
	}
	if countTable(t, s, "ssh_failures") != 0 || sshBanCount(t, s) != 0 || s.ssh.count("h", ip, store.NowMS()) != 0 {
		t.Fatalf("attempt stuck rows=%d bans=%d window=%d", countTable(t, s, "ssh_failures"), sshBanCount(t, s), s.ssh.count("h", ip, store.NowMS()))
	}
	if n := len(sshHitRows(t, s)); n != 0 {
		t.Fatalf("hit stuck in summary %d", n)
	}
	if _, err := s.st.DB.Exec(`DROP TRIGGER fail_ssh_ban`); err != nil {
		t.Fatal(err)
	}
	mustSSH(t, s, cert, "", evs...)
	if sshBanCount(t, s) != 1 || countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
		t.Fatalf("redelivery bans=%d rows=%d window=%d", sshBanCount(t, s), countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
	}
	mustSSH(t, s, cert, "", evs...)
	if sshBanCount(t, s) != 1 || countTable(t, s, "ssh_failures") != 0 || s.ssh.count("h", ip, store.NowMS()) != 5 {
		t.Fatal("replay after redelivery", sshBanCount(t, s), countTable(t, s, "ssh_failures"), s.ssh.count("h", ip, store.NowMS()))
	}
}

func sshHitRows(t *testing.T, s *Server) map[string]string {
	t.Helper()
	rows, err := s.st.DB.Query(`SELECT k, v FROM settings WHERE k >= 'sh:' AND k < 'sh;' ORDER BY k`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func sshEv(id string, seq, observed, stored int64, ip string) protocol.Event {
	if stored == 0 {
		stored = observed
	}
	raw, _ := json.Marshal(protocol.SSHPayload{RemoteIP: ip, User: "root", Note: "Failed password", ObservedAtMS: stored})
	return protocol.Event{EventID: id, Seq: seq, Kind: "ssh", ObservedAtMS: observed, Payload: raw}
}

func sshBurst(prefix, ip string, n int, at int64) []protocol.Event {
	evs := make([]protocol.Event, 0, n)
	for i := 1; i <= n; i++ {
		evs = append(evs, sshEv(prefix+"-"+string(rune('0'+i)), int64(i), at, 0, ip))
	}
	return evs
}

func sendLane(t *testing.T, s *Server, cert *x509.Certificate, lane string, events ...protocol.Event) (int, protocol.Ack) {
	t.Helper()
	raw, err := json.Marshal(protocol.Batch{Session: s.session, Instance: "test-process", Lane: lane, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	s.handleBatch(w, r)
	var ack protocol.Ack
	if w.Code == 200 || w.Code == 409 {
		if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, ack
}

func mustSSH(t *testing.T, s *Server, cert *x509.Certificate, lane string, evs ...protocol.Event) {
	t.Helper()
	code, ack := sendLane(t, s, cert, lane, evs...)
	if code != 200 || len(ack.Ack) != len(evs) {
		t.Fatalf("ssh %d %+v", code, ack)
	}
}

func sshBanCount(t *testing.T, s *Server) int {
	t.Helper()
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM blocks WHERE source='ssh' AND state='active'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func insertSSHRow(t *testing.T, s *Server, id, ip string, at int64) {
	t.Helper()
	addr, err := netipx.Parse(ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO ssh_failures(event_id,host_id,observed_at_ms,remote_ip,remote_ip_bin) VALUES(?,?,?,?,?)`,
		id, "h", at, netipx.Canonical(addr), netipx.Bin16(addr)); err != nil {
		t.Fatal(err)
	}
}

func sshLine(rows [][]string, ip string) []string {
	for _, r := range rows {
		if len(r) > 0 && r[0] == ip {
			return r
		}
	}
	return nil
}

func sameRows(t *testing.T, got, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rows %d want %d\ngot %v\nwant %v", len(got), len(want), got, want)
	}
	for i := range got {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("row %d %v vs %v", i, got[i], want[i])
		}
		for j := range got[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("row %d col %d %q want %q", i, j, got[i][j], want[i][j])
			}
		}
	}
}
