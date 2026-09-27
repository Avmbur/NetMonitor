package collect

import (
	"database/sql"
	"net/netip"
	"testing"

	"strings"

	"netmonitor/internal/store"
)

func TestDumpDeltaOnce(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	src := netip.MustParseAddr("192.168.10.180")
	dst := netip.MustParseAddr("1.1.1.1")
	sp, dp := 1, 443
	e1 := Entry{IPVersion: 4, Protocol: "tcp", State: "ESTABLISHED", OrigSrc: src, OrigDst: dst, OrigSport: &sp, OrigDport: &dp, OrigPackets: 10, OrigBytes: 100, ReplyPackets: 5, ReplyBytes: 50, Assured: true, CountersKnown: true}
	opt := DumpOpts{HostID: "h", BootID: "b", Local: []netip.Addr{src}, NowMS: 1000, MonoMS: 1000}
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{e1}, opt) }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='flow'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("flow events %d", n)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='sample'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("first dump must not sample, got %d", n)
	}
	e2 := e1
	e2.OrigBytes = 250
	e2.ReplyBytes = 80
	opt.NowMS = 16000
	opt.MonoMS = 16000
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{e2}, opt) }); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='sample'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("samples %d", n)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='flow'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("unchanged dump sent extra flow %d", n)
	}
	var payload string
	if err := st.DB.QueryRow(`SELECT payload FROM outbox WHERE kind='sample'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"orig_bytes_delta":150`) || !strings.Contains(payload, `"reply_bytes_delta":30`) {
		t.Fatalf("payload %s", payload)
	}
}

func TestScopeOriginAndSkipIfaces(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	local := netip.MustParseAddr("172.17.0.1")
	remote := netip.MustParseAddr("172.17.0.8")
	sp, dp := 40000, 80
	e := Entry{IPVersion: 4, Protocol: "tcp", State: "ESTABLISHED", OrigSrc: remote, OrigDst: local, OrigSport: &sp, OrigDport: &dp, Assured: true, CountersKnown: true}
	opt := DumpOpts{
		HostID: "h", BootID: "b", Local: []netip.Addr{local}, NowMS: 1000, MonoMS: 1000,
		AddrIface:  map[string]string{local.String(): "docker0"},
		DockerNets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")},
	}
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{e}, opt) }); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='flow'`).Scan(&n)
	if n != 0 {
		t.Fatal("inter-container observed")
	}
	opt.ObserveDocker = true
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{e}, opt) }); err != nil {
		t.Fatal(err)
	}
	var payload string
	st.DB.QueryRow(`SELECT payload FROM outbox WHERE kind='flow'`).Scan(&payload)
	if !strings.Contains(payload, `"origin":"docker"`) {
		t.Fatal(payload)
	}
	st.DB.Exec("DELETE FROM outbox")
	hostIP := netip.MustParseAddr("192.168.10.180")
	wan := netip.MustParseAddr("1.1.1.1")
	host := Entry{IPVersion: 4, Protocol: "tcp", State: "ESTABLISHED", OrigSrc: hostIP, OrigDst: wan, OrigSport: &sp, OrigDport: &dp, Assured: true, CountersKnown: true}
	hostOpt := DumpOpts{
		HostID: "h", BootID: "b2", Local: []netip.Addr{hostIP}, NowMS: 2000, MonoMS: 2000,
		AddrIface:  map[string]string{hostIP.String(): "eth0"},
		SkipIfaces: map[string]bool{"eth0": true},
	}
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{host}, hostOpt) }); err != nil {
		t.Fatal(err)
	}
	st.DB.QueryRow(`SELECT COUNT(*) FROM outbox WHERE kind='flow'`).Scan(&n)
	if n != 0 {
		t.Fatal("skipped iface observed")
	}
	hostOpt.SkipIfaces = nil
	hostOpt.LAN = []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}
	hostOpt.Own = []netip.Prefix{netip.MustParsePrefix("192.168.10.181/32")}
	own := Entry{IPVersion: 4, Protocol: "tcp", State: "ESTABLISHED", OrigSrc: hostIP, OrigDst: netip.MustParseAddr("192.168.10.181"), OrigSport: &sp, OrigDport: &dp, Assured: true, CountersKnown: true}
	if err := st.Update(func(tx *sql.Tx) error { return ApplyDump(tx, []Entry{own}, hostOpt) }); err != nil {
		t.Fatal(err)
	}
	st.DB.QueryRow(`SELECT payload FROM outbox WHERE kind='flow'`).Scan(&payload)
	if !strings.Contains(payload, `"origin":"host"`) || !strings.Contains(payload, `"remote_scope":"own"`) {
		t.Fatal(payload)
	}
}
