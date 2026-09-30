package agent

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"netmonitor/internal/collect"

	pol "netmonitor/internal/policy"
	"netmonitor/internal/store"
)

func TestAlertGroupKeepsQuestion(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Agent{st: st, managed: true, mode: "park"}
	a.groups = []pol.Rule{{ID: "g1", Name: "Телеметрия", Enabled: true, Action: "alert", Version: 1,
		Match: pol.Match{Networks: []string{"203.0.113.50/32"}}}}
	a.enqueueLearnProcess("out", "tcp", "203.0.113.50", 0, 9, collect.Process{Comm: "curl", Path: "/usr/bin/curl"}, "")
	var n int
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 1 {
		t.Fatal("alert group did not raise a question", n)
	}
}

func TestInboundReplyDoesNotAsk(t *testing.T) {
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
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Agent{st: st, managed: true, mode: "learn"}
	sp, dp := 443, 51950
	for collect.Listening("tcp", dp) {
		dp++
	}
	remote := netip.MustParseAddr("8.6.112.0")
	reply := collect.Entry{IPVersion: 4, Protocol: "tcp", OrigSrc: remote, OrigDst: local, OrigSport: &sp, OrigDport: &dp, TCPFlagsKnown: true, TCPFlags: 0x10}
	a.noteLearn(reply, true)
	var n int
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 0 {
		t.Fatal("reply opened an inbound question", n)
	}
	syn := reply
	syn.TCPFlags = 0x02
	dp = 22
	syn.OrigDport = &dp
	a.noteLearn(syn, true)
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 1 {
		t.Fatal("inbound SYN did not ask", n)
	}
}

func TestDockerForwardQuestions(t *testing.T) {
	var local netip.Addr
	for _, a := range collect.LocalAddrs() {
		if a.IsValid() {
			local = a.Unmap()
			if !a.IsLoopback() {
				break
			}
		}
	}
	if !local.IsValid() {
		t.Skip("no local address")
	}
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Agent{st: st, managed: true, mode: "learn",
		dockerNets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")},
		containers: map[string]string{"172.17.0.2": "web"}}
	sp, web, out := 40000, 443, 8080
	box := netip.MustParseAddr("172.17.0.2")
	ext := netip.MustParseAddr("1.1.1.1")
	a.noteLearn(collect.Entry{Protocol: "tcp", OrigSrc: box, OrigDst: ext, OrigSport: &sp, OrigDport: &web}, true)
	client := netip.MustParseAddr("203.0.113.8")
	a.noteLearn(collect.Entry{Protocol: "tcp", OrigSrc: client, OrigDst: local, OrigSport: &sp, OrigDport: &out, ReplySrc: box}, true)
	a.noteLearn(collect.Entry{Protocol: "udp", OrigSrc: client, OrigDst: local, OrigSport: &sp, OrigDport: &out, ReplySrc: box, CTDirectionKnown: true, CTReply: true}, true)
	rows, err := st.DB.Query(`SELECT payload FROM local_questions ORDER BY created_at_ms`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	if len(got) != 2 {
		t.Fatal(got)
	}
	if !strings.Contains(got[0], `"direction":"out"`) || !strings.Contains(got[0], `"container":"web"`) || !strings.Contains(got[0], `"remote_port":443`) {
		t.Fatal(got[0])
	}
	if !strings.Contains(got[1], `"direction":"in"`) || !strings.Contains(got[1], `"local_port":8080`) || !strings.Contains(got[1], `"container":"web"`) {
		t.Fatal(got[1])
	}
}

// Имя свежего контейнера появляется в config.v2.json позже первых пакетов:
// второй отброс того же соединения не должен открыть второй вопрос.
func TestContainerQuestionGetsNameLater(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	nets := []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}
	a := &Agent{st: st, managed: true, mode: "learn", dockerNets: nets,
		containers: map[string]string{}, containersAt: time.Now().Add(time.Hour), containerNets: nets}
	sp, dp := 40000, 80
	e := collect.Entry{Protocol: "tcp", OrigSrc: netip.MustParseAddr("172.17.0.2"), OrigDst: netip.MustParseAddr("1.0.0.1"), OrigSport: &sp, OrigDport: &dp}
	a.noteLearn(e, true)
	a.contMu.Lock()
	a.containers = map[string]string{"172.17.0.2": "fresh"}
	a.contMu.Unlock()
	a.noteLearn(e, true)
	var n int
	var p string
	if err = st.DB.QueryRow(`SELECT COUNT(*), MAX(payload) FROM local_questions`).Scan(&n, &p); err != nil {
		t.Fatal(err)
	}
	if n != 1 || !strings.Contains(p, `"container":"fresh"`) {
		t.Fatalf("%d %s", n, p)
	}
}

func TestAlertGroupReplyDoesNotAsk(t *testing.T) {
	local := netip.Addr{}
	for _, ip := range collect.LocalAddrs() {
		if ip.IsValid() {
			local = ip.Unmap()
			break
		}
	}
	if !local.IsValid() {
		t.Fatal("no local address")
	}
	remote := netip.MustParseAddr("203.0.113.50")
	for _, mode := range []string{"allow", "learn", "block"} {
		for _, proto := range []string{"tcp", "udp", "icmp"} {
			t.Run(mode+"/"+proto, func(t *testing.T) {
				st, err := store.OpenAgent(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer st.Close()
				a := &Agent{st: st, managed: true, mode: mode}
				a.groups = []pol.Rule{{ID: "g1", Enabled: true, Action: "alert",
					Match: pol.Match{Networks: []string{remote.String() + "/32"}}}}
				sp, dp := 443, 51950
				e := collect.Entry{IPVersion: 4, Protocol: proto, OrigSrc: remote, OrigDst: local,
					CTDirectionKnown: true, CTReply: true, TCPFlagsKnown: proto == "tcp", TCPFlags: 0x10}
				if proto != "icmp" {
					e.OrigSport, e.OrigDport = &sp, &dp
				}
				count := func(want int) {
					t.Helper()
					var n int
					if err := st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n); err != nil {
						t.Fatal(err)
					}
					if n != want {
						t.Fatalf("questions=%d, want %d", n, want)
					}
				}
				// A group can drop an incoming reply before the policy tail.
				a.noteLearn(e, true)
				count(0)
				// A genuine incoming contact still asks. Conntrack's original
				// direction must take precedence over the TCP ACK heuristic.
				e.CTReply = false
				a.noteLearn(e, true)
				count(1)
				// The original outgoing contact asks separately, not its reply.
				e.OrigSrc, e.OrigDst = local, remote
				e.OrigSport, e.OrigDport = e.OrigDport, e.OrigSport
				a.noteLearn(e, true)
				count(2)
			})
		}
	}
}
