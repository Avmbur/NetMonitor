package agent

import (
	"net/netip"
	"testing"

	"netmonitor/internal/collect"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestDumpNotesShareOneCommit(t *testing.T) {
	local := localTestAddr(t)
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Agent{st: st, mode: "learn"}
	sp := 40000
	dp := 8080
	var entries []collect.Entry
	for i, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		remote := netip.MustParseAddr(ip)
		p := sp + i
		entries = append(entries, collect.Entry{
			IPVersion: 4, Protocol: "tcp", State: "SYN_SENT", Unreplied: true,
			OrigSrc: remote, OrigDst: local, OrigSport: &p, OrigDport: &dp,
			TCPFlagsKnown: true, TCPFlags: 0x02,
		})
	}
	if err := a.queueDumpNotes(entries); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM local_questions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("questions %d", n)
	}
	err = a.enqueueAll([]outItem{
		{kind: "health", pri: 8, payload: protocol.HealthPayload{Kind: "ok"}},
		{kind: "health", pri: 8, payload: make(chan int)},
	})
	if err == nil {
		t.Fatal("bad payload committed")
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='health'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("partial health commit %d", n)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM local_questions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("questions after rollback %d", n)
	}
}

func localTestAddr(t *testing.T) netip.Addr {
	t.Helper()
	var local netip.Addr
	for _, a := range collect.LocalAddrs() {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap()
		if local.IsValid() && a.IsLoopback() {
			continue
		}
		local = a
		if !a.IsLoopback() {
			break
		}
	}
	if !local.IsValid() {
		t.Skip("no local address")
	}
	return local
}
