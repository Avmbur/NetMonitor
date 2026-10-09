package agent

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"netmonitor/internal/collect"
	"netmonitor/internal/fw"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func newSpool(t *testing.T) (*Agent, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{st: st, cfg: Config{DataDir: dir}, session: "test-session"}
	a.prepareSpool()
	if err = a.recoverSpool(); err != nil {
		st.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a.st != nil {
			_ = a.st.Close()
		}
	})
	return a, st, dir
}

func countSQL(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func metaVal(t *testing.T, db *sql.DB, k string) string {
	t.Helper()
	var v string
	err := db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func dumpBytes(t *testing.T, a *Agent, n, now int64) {
	t.Helper()
	if err := dumpBytesErr(a, n, now); err != nil {
		t.Fatal(err)
	}
}

func dumpBytesErr(a *Agent, n, now int64) error {
	e, opt := spoolObservation(n, now)
	return a.collectMem(func(book *collect.Mem) error { return book.ApplyDump([]collect.Entry{e}, opt) })
}

func spoolObservation(n, now int64) (collect.Entry, collect.DumpOpts) {
	src := netip.MustParseAddr("192.168.10.180")
	dst := netip.MustParseAddr("1.1.1.1")
	sp, dp := 1, 443
	e := collect.Entry{
		IPVersion: 4, Protocol: "tcp", State: "ESTABLISHED",
		OrigSrc: src, OrigDst: dst, OrigSport: &sp, OrigDport: &dp,
		OrigPackets: 10, OrigBytes: n, ReplyPackets: 5, ReplyBytes: 50,
		Assured: true, CountersKnown: true,
	}
	opt := collect.DumpOpts{HostID: "h", BootID: "b", Local: []netip.Addr{src}, NowMS: now, MonoMS: now}
	return e, opt
}

func deltasOf(t *testing.T, items []planItem) []int64 {
	t.Helper()
	var out []int64
	for _, it := range items {
		if it.kind != "sample" {
			continue
		}
		var sp protocol.SamplePayload
		if err := json.Unmarshal([]byte(it.payload), &sp); err != nil {
			t.Fatal(err)
		}
		out = append(out, sp.OrigBytesDelta)
	}
	return out
}

func serveBatches(t *testing.T, a *Agent, fail *bool) *[]protocol.Event {
	t.Helper()
	got := &[]protocol.Event{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b protocol.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
			return
		}
		*got = append(*got, b.Events...)
		if fail != nil && *fail {
			w.WriteHeader(500)
			return
		}
		ack := protocol.Ack{}
		for _, ev := range b.Events {
			ack.Ack = append(ack.Ack, ev.EventID)
		}
		json.NewEncoder(w).Encode(ack)
	}))
	t.Cleanup(srv.Close)
	if a.session == "" {
		a.adoptSession("test-session")
	}
	a.client = srv.Client()
	a.cfg.Monitor = srv.URL
	return got
}

func TestUrgentWritesWhilePlannedStaysInMemory(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	if err := a.Enqueue("flow", 5, map[string]string{"k": "flow"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("sample", 0, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("firewall", 8, protocol.FirewallPayload{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("question", 7, protocol.QuestionPayload{RemoteIP: "203.0.113.9", Direction: "in", Protocol: "tcp", RemotePort: 25}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("dns", 6, protocol.DNSPayload{Name: "a.example", IP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Enqueue("scan", 9, protocol.ScanPayload{IP: "203.0.113.8", Ports: []int{22}}); err != nil {
		t.Fatal(err)
	}
	if err := a.saveSSH([]collect.SSHFail{{IP: "203.0.113.7", AtMS: store.NowMS()}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.saveLocal(1, fw.Policy{Mode: "enforce"}, nil); err != nil {
		t.Fatal(err)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind IN ('flow','sample','firewall')`); n != 0 {
		t.Fatalf("planned rows on disk: %d", n)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM checkpoints`); n != 0 {
		t.Fatalf("checkpoints on disk: %d", n)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM local_questions`); n != 1 {
		t.Fatalf("questions %d", n)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM local_policy`); n != 1 {
		t.Fatalf("policy %d", n)
	}
	for _, kind := range []string{"question"} {
		if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind=?`, kind); n != 1 {
			t.Fatalf("%s on disk: %d", kind, n)
		}
	}
	if len(a.plan.copy()) != 6 {
		t.Fatalf("memory events %d", len(a.plan.copy()))
	}

}

func TestAckBeforeFlushDropsTheGroup(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	fail := false
	got := serveBatches(t, a, &fail)
	for i := 0; i < 3; i++ {
		if err := a.Enqueue("sample", 0, map[string]int{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox`); n != 0 {
		t.Fatalf("queued early %d", n)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 3 {
		t.Fatalf("sent %d", len(*got))
	}
	if len(a.plan.copy()) != 0 {
		t.Fatal("acked group still in memory")
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox`); n != 0 {
		t.Fatalf("acked rows resurrected %d", n)
	}
}

func TestNewMonitorSessionDropsTelemetry(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	if err := a.Enqueue("sample", 0, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if len(a.plan.copy()) != 1 {
		t.Fatal("sample missing")
	}
	a.adoptSession("s1")
	if len(a.plan.copy()) != 0 {
		t.Fatal("old sample kept")
	}
	if !a.takeDump() {
		t.Fatal("snapshot not requested")
	}
	before := metaVal(t, st.DB, "next_seq")
	if err := a.Enqueue("sample", 0, map[string]int{"n": 2}); err != nil {
		t.Fatal(err)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind='sample'`); n != 0 {
		t.Fatalf("sample reached disk %d", n)
	}
	if metaVal(t, st.DB, "next_seq") != before {
		t.Fatalf("seq moved %s -> %s", before, metaVal(t, st.DB, "next_seq"))
	}
	a.adoptSession("s1")
	if a.takeDump() {
		t.Fatal("same session dumped again")
	}
}

func TestIdleLaneSkipsDiskUntilNewEvent(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	if a.shouldPoll("history") {
		t.Fatal("empty telemetry lane must not read disk")
	}
	a.spoolMu.Lock()
	a.markDiskIdle("history", true)
	a.markDiskIdle("urgent", true)
	a.spoolMu.Unlock()
	if a.shouldPoll("history") || a.shouldPoll("urgent") {
		t.Fatal("idle lane still polling")
	}
	if err := a.Enqueue("sample", 0, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if !a.shouldPoll("history") {
		t.Fatal("sample stayed invisible")
	}
	if a.shouldPoll("urgent") {
		t.Fatal("sample woke the urgent lane")
	}
	if err := a.Enqueue("health", 10, protocol.HealthPayload{Kind: "alive"}); err != nil {
		t.Fatal(err)
	}
	if !a.shouldPoll("heartbeat") {
		t.Fatal("health stayed invisible")
	}
}

func TestLostAckResendsSameID(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	if err := a.Enqueue("flow", 5, map[string]string{"k": "once"}); err != nil {
		t.Fatal(err)
	}
	fail := true
	got := serveBatches(t, a, &fail)
	if err := a.Flush(); err == nil {
		t.Fatal("lost ack hidden")
	}
	if len(*got) != 1 {
		t.Fatalf("first send %d", len(*got))
	}
	id, seq := (*got)[0].EventID, (*got)[0].Seq
	next := metaVal(t, st.DB, "next_seq")
	fail = false
	*got = nil
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0].EventID != id || (*got)[0].Seq != seq {
		t.Fatalf("resent %+v want %s %d", *got, id, seq)
	}
	if metaVal(t, st.DB, "next_seq") != next {
		t.Fatal("resend took a new seq")
	}
	if len(a.plan.copy()) != 0 {
		t.Fatal("acked event still planned")
	}
}

func TestSpoolCrashRebasesCounters(t *testing.T) {
	a, st, dir := newSpool(t)
	dumpBytes(t, a, 100, 1000)
	dumpBytes(t, a, 250, 16000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 1 || ds[0] != 150 {
		t.Fatal(ds)
	}
	if countSQL(t, st.DB, "SELECT COUNT(*) FROM checkpoints") != 0 || countSQL(t, st.DB, "SELECT COUNT(*) FROM outbox") != 0 {
		t.Fatal("telemetry reached disk")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenAgent(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a = &Agent{st: st, session: "test-session", cfg: Config{DataDir: dir}}
	if err = a.recoverSpool(); err != nil {
		t.Fatal(err)
	}
	dumpBytes(t, a, 400, 31000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 0 {
		t.Fatalf("old baseline restored: %v", ds)
	}
	dumpBytes(t, a, 450, 46000)
	if ds := deltasOf(t, a.plan.copy()); len(ds) != 1 || ds[0] != 50 {
		t.Fatal(ds)
	}
}
