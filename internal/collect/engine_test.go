package collect

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"netmonitor/internal/protocol"
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

func TestMakeFlowNamesContainer(t *testing.T) {
	netw := netip.MustParsePrefix("172.17.0.0/16")
	box := netip.MustParseAddr("192.168.10.186")
	c1 := netip.MustParseAddr("172.17.0.2")
	out := netip.MustParseAddr("1.1.1.1")
	sp, dp := 40000, 443
	e := Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: out, OrigSport: &sp, OrigDport: &dp}
	fp := makeFlow(e, DumpOpts{Local: []netip.Addr{box}, DockerNets: []netip.Prefix{netw}, NowMS: 1,
		Container: func(ip string) string {
			if ip == c1.String() {
				return "web"
			}
			return ""
		}})
	if fp.Direction != "out" || fp.Origin != "docker" || fp.Container != "web" || fp.RemoteIP != out.String() {
		t.Fatalf("%s %s %s %s", fp.Direction, fp.Origin, fp.Container, fp.RemoteIP)
	}
}

// Вход на опубликованный порт: по порту 8080 на хосте слушает docker-proxy,
// но соединение принадлежит контейнеру — процесс хоста к нему не приписываем.
func TestPublishedPortFlowHasNoHostProcess(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box := netip.MustParseAddr("192.168.10.186")
	c1 := netip.MustParseAddr("172.17.0.3")
	client := netip.MustParseAddr("192.168.20.50")
	sp, pub := 50000, 8080
	id := int64(7)
	e := Entry{Protocol: "tcp", OrigSrc: client, OrigDst: box, OrigSport: &sp, OrigDport: &pub,
		ReplySrc: c1, ReplyDst: client, CTID: &id, StartNS: 1}
	opt := DumpOpts{HostID: "h", BootID: "b", Local: []netip.Addr{box}, DockerNets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}, NowMS: 1,
		Process: func(Entry) Process {
			return Process{Comm: "docker-proxy", Path: "/usr/bin/docker-proxy", Cgroup: "/system.slice/docker.service"}
		},
		Container: func(ip string) string { return map[string]string{c1.String(): "pub"}[ip] }}
	if err = st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, e, "new", opt) }); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err = st.DB.QueryRow(`SELECT payload FROM outbox WHERE kind='flow'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "docker-proxy") || !strings.Contains(payload, `"container":"pub"`) || !strings.Contains(payload, `"local_port":8080`) {
		t.Fatal(payload)
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

func TestDockerAttributionUpdatesExistingFlow(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		name := "outgoing"
		if inbound {
			name = "published"
		}
		t.Run(name, func(t *testing.T) {
			st, err := store.OpenAgent(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			box := netip.MustParseAddr("192.168.10.186")
			container := netip.MustParseAddr("172.17.0.2")
			peer := netip.MustParseAddr("203.0.113.50")
			sp, dp := 40000, 8080
			id := int64(7)
			e := Entry{IPVersion: 4, Protocol: "tcp", OrigSrc: container, OrigDst: peer, ReplySrc: peer,
				OrigSport: &sp, OrigDport: &dp, CTID: &id, StartNS: 1}
			wantDir := "out"
			if inbound {
				e.OrigSrc, e.OrigDst, e.ReplySrc = peer, box, container
				wantDir = "in"
			}
			opt := DumpOpts{HostID: "h", BootID: "b", Local: []netip.Addr{box}, NowMS: 1, MonoMS: 1,
				Process: func(Entry) Process {
					return Process{Comm: "docker-proxy", Path: "/usr/bin/docker-proxy", Cgroup: "/system.slice/docker.service"}
				}}
			apply := func(kind string) {
				t.Helper()
				if err := st.Update(func(tx *sql.Tx) error { return ApplyEvent(tx, e, kind, opt) }); err != nil {
					t.Fatal(err)
				}
			}
			apply("new")
			opt.DockerNets = []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}
			opt.NowMS, opt.MonoMS = 2, 2
			apply("dump")
			var raw string
			var count int
			if err := st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='flow'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatalf("Docker reclassification did not send flow: %d", count)
			}
			if err := st.DB.QueryRow("SELECT payload FROM outbox WHERE kind='flow' ORDER BY seq DESC LIMIT 1").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var flow protocol.FlowPayload
			if err := json.Unmarshal([]byte(raw), &flow); err != nil {
				t.Fatal(err)
			}
			if flow.Direction != wantDir || flow.Origin != "docker" || flow.ProcComm != "" || flow.ProcPath != "" || flow.ProcCgroup != "" || flow.ProcUID != nil {
				t.Fatalf("stale process/direction: %+v", flow)
			}
			opt.Container = func(ip string) string {
				if ip == container.String() {
					return "pub"
				}
				return ""
			}
			opt.NowMS, opt.MonoMS = 3, 3
			apply("dump")
			if err := st.DB.QueryRow("SELECT COUNT(*) FROM outbox WHERE kind='flow'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 3 {
				t.Fatalf("late name did not send flow: %d", count)
			}
		})
	}
}
