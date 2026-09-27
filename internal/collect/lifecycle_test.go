package collect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"testing"
	"time"
)

func fixture() (Entry, DumpOpts) {
	src := netip.MustParseAddr("10.10.0.2")
	dst := netip.MustParseAddr("203.0.113.10")
	sp, dp := 42000, 443
	id := int64(123)
	e := Entry{IPVersion: 4, Protocol: "tcp", State: "SYN_SENT", OrigSrc: src, OrigDst: dst, OrigSport: &sp, OrigDport: &dp, CTID: &id, StartNS: 1_000_000_000, CountersKnown: true, OrigBytes: 100, OrigPackets: 1, Unreplied: true}
	o := DumpOpts{HostID: "host", BootID: "boot", Namespace: "net:[123]", Local: []netip.Addr{src}, NowMS: 10000, MonoMS: 1000}
	return e, o
}
func events(t *testing.T, st *store.Store, kind string) []json.RawMessage {
	t.Helper()
	rows, e := st.DB.Query("SELECT payload FROM outbox WHERE kind=? ORDER BY seq", kind)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var s string
		if e = rows.Scan(&s); e != nil {
			t.Fatal(e)
		}
		out = append(out, json.RawMessage(s))
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestLifecycleReuseAndRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, o := fixture()
	o.Process = func(Entry) Process { u := 1000; return Process{"curl", "/usr/bin/curl", "/user.slice", &u} }
	apply := func(kind string) {
		t.Helper()
		if err := st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, e, kind, o) }); err != nil {
			t.Fatal(err)
		}
	}
	apply("new")
	uid := ""
	var f protocol.FlowPayload
	json.Unmarshal(events(t, st, "flow")[0], &f)
	uid = f.FlowUID
	if f.ProcComm != "curl" || f.Incomplete != 0 {
		t.Fatalf("%+v", f)
	}
	st.Close()
	st, err = store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	o.NowMS += 1000
	o.MonoMS += 1000
	e.OrigBytes += 40
	e.State = "ESTABLISHED"
	e.ReplyBytes = 80
	e.Unreplied = false
	apply("update")
	o.NowMS += 1000
	o.MonoMS += 1000
	e.State = "TIME_WAIT"
	apply("destroy")
	n := len(events(t, st, "flow"))
	apply("destroy")
	if len(events(t, st, "flow")) != n {
		t.Fatal("duplicate DESTROY created another flow")
	}
	fs := events(t, st, "flow")
	for _, raw := range fs {
		json.Unmarshal(raw, &f)
		if f.FlowUID != uid {
			t.Fatal("restart changed identity")
		}
	}
	if f.EndedAtMS == nil || f.CloseReason != "fin" || f.ReplySeen != 1 {
		t.Fatalf("close %+v", f)
	}
	id := int64(124)
	e.CTID = &id
	e.StartNS += 5_000_000_000
	e.State = "SYN_SENT"
	o.NowMS += 1000
	o.MonoMS += 1000
	apply("new")
	fs = events(t, st, "flow")
	json.Unmarshal(fs[len(fs)-1], &f)
	if f.FlowUID == uid {
		t.Fatal("tuple reuse merged")
	}
	// Old DESTROY cannot close the replacement.
	old, _ := fixture()
	if err = st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, old, "destroy", o) }); err != nil {
		t.Fatal(err)
	}
	var raw string
	st.DB.QueryRow("SELECT payload FROM checkpoints").Scan(&raw)
	var cp checkpoint
	json.Unmarshal([]byte(raw), &cp)
	if cp.Flow.EndedAtMS != nil {
		t.Fatal("late destroy closed replacement")
	}
}
func TestDumpDoesNotCloseNewerEventAndMarksMissing(t *testing.T) {
	st, e := store.OpenAgent(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	flow, o := fixture()
	must := func(fn func(*sql.Tx) error) {
		t.Helper()
		if e := st.Update(fn); e != nil {
			t.Fatal(e)
		}
	}
	must(func(tx *sql.Tx) error { return ApplyEvent(tx, flow, "new", o) })
	o.NowMS += 1000
	o.MonoMS += 1000
	flow.CountersKnown = false
	must(func(tx *sql.Tx) error { return ApplyEvent(tx, flow, "update", o) })
	o.NowMS += 1000
	o.MonoMS += 1000
	o.SnapshotMono = 1500
	must(func(tx *sql.Tx) error { return ApplyDump(tx, nil, o) })
	for _, raw := range events(t, st, "flow") {
		var f protocol.FlowPayload
		json.Unmarshal(raw, &f)
		if f.EndedAtMS != nil {
			t.Fatal("stale dump closed new event")
		}
	}
	o.SnapshotMono = 3000
	must(func(tx *sql.Tx) error { return ApplyDump(tx, nil, o) })
	fs := events(t, st, "flow")
	var f protocol.FlowPayload
	json.Unmarshal(fs[len(fs)-1], &f)
	if f.EndedAtMS == nil || f.CloseReason != "unknown" {
		t.Fatalf("%+v", f)
	}
}
func TestClockJumpAndCounterReset(t *testing.T) {
	st, e := store.OpenAgent(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	f, o := fixture()
	o.NowMS = 1_000_000
	apply := func() {
		t.Helper()
		if e := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{f}, o) }); e != nil {
			t.Fatal(e)
		}
	}
	apply()
	f.OrigBytes += 1500
	o.MonoMS += 15000
	o.NowMS -= 120000
	apply()
	var p protocol.SamplePayload
	json.Unmarshal(events(t, st, "sample")[0], &p)
	if p.T1MS-p.T0MS != 15000 || p.OrigBytesDelta != 1500 || p.Quality != "ok" {
		t.Fatalf("%+v", p)
	}
	if len(events(t, st, "health")) != 1 {
		t.Fatal("clock jump missing")
	}
	o.NowMS += 15000
	o.MonoMS += 15000
	f.OrigBytes = 1
	apply()
	ss := events(t, st, "sample")
	json.Unmarshal(ss[len(ss)-1], &p)
	if p.Quality != "counter_reset" || p.OrigBytesDelta != 0 {
		t.Fatalf("%+v", p)
	}
}
func TestICMPUnknownCountersAndNoPorts(t *testing.T) {
	st, e := store.OpenAgent(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	f, o := fixture()
	typ, code := 8, 0
	f.Protocol = "icmp"
	f.ICMPType = &typ
	f.ICMPCode = &code
	f.OrigSport = nil
	f.OrigDport = nil
	f.CountersKnown = false
	if e = st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, f, "new", o) }); e != nil {
		t.Fatal(e)
	}
	var p protocol.FlowPayload
	json.Unmarshal(events(t, st, "flow")[0], &p)
	if p.LocalPort != nil || p.RemotePort != nil || p.OrigBytes != nil || p.ICMPType == nil || *p.ICMPType != 8 {
		t.Fatalf("%+v", p)
	}
}
func TestFirewallAggregation(t *testing.T) {
	a := FirewallLog{}
	now := time.Now()
	port := 443
	p := protocol.FirewallPayload{LocalIP: "10.0.0.2", RemoteIP: "1.1.1.1", Protocol: "tcp", Direction: "out", RemotePort: &port, Hits: 1}
	first := a.Observe(p, now)
	if len(first) != 1 {
		t.Fatal("first delayed")
	}
	for i := 0; i < 9; i++ {
		if len(a.Observe(p, now.Add(time.Second))) != 0 {
			t.Fatal("repeated detail")
		}
	}
	last := a.Flush(now.Add(10 * time.Second))
	if len(last) != 1 || last[0].Hits != 9 || last[0].GroupID != first[0].GroupID {
		t.Fatal(fmt.Sprint(last))
	}
}

func TestShortFlowCountsTrafficBeforeFirstDump(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e, o := fixture()
	e.CountersKnown = false
	if err = st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, e, "new", o) }); err != nil {
		t.Fatal(err)
	}
	// The entire flow fits in one millisecond and NEW contained no counters.
	e.CountersKnown = true
	e.OrigBytes = 160
	e.ReplyBytes = 80
	e.OrigPackets = 2
	e.ReplyPackets = 1
	if err = st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, e, "destroy", o) }); err != nil {
		t.Fatal(err)
	}
	ss := events(t, st, "sample")
	if len(ss) != 1 {
		t.Fatal("short flow traffic lost", len(ss))
	}
	var p protocol.SamplePayload
	json.Unmarshal(ss[0], &p)
	if p.OrigBytesDelta != 160 || p.ReplyBytesDelta != 80 || p.T1MS <= p.T0MS {
		t.Fatalf("%+v", p)
	}
}
