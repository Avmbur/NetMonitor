package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	pol "netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
)

func TestMonitorAdmitIsAckedOnlyAfterFilterAccepts(t *testing.T) {
	resetAdmittedForTest(t)
	a, _, reports, _ := agentFixture(t)
	old := admitAddrs
	t.Cleanup(func() { admitAddrs = old })
	var got []netip.Addr
	var ttl time.Duration
	var fail error
	admitAddrs = func(ips []netip.Addr, d time.Duration) error {
		got, ttl = ips, d
		return fail
	}
	payload, err := svcnet.Payload([]netip.Addr{netip.MustParseAddr("140.82.121.6")})
	if err != nil {
		t.Fatal(err)
	}
	pr := policy(1)
	pr.Commands = []protocol.Command{{ID: "adm", Kind: svcnet.AdmitKind, Payload: payload}}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "140.82.121.6" || ttl != svcnet.AdmitTTL {
		t.Fatal(got, ttl)
	}
	last := (*reports)[len(*reports)-1]
	if !slices.Contains(last.Ack, "adm") {
		t.Fatalf("admitted address not confirmed: %+v", last)
	}
	fail = errors.New("nft: no such set")
	pr.Commands = []protocol.Command{{ID: "adm2", Kind: svcnet.AdmitKind, Payload: payload}, {ID: "bad", Kind: svcnet.AdmitKind, Payload: `{"ips":["127.0.0.1"],"ttl_ms":600000}`}}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	last = (*reports)[len(*reports)-1]
	if len(last.Ack) != 0 || !slices.Contains(last.Status.CommandIDs, "adm2") {
		t.Fatalf("failed admission confirmed: %+v", last)
	}
}

// Адрес, вписанный в служебный набор, проверка вопроса считает покрытым
// служебным правилом, как и фильтр. Чужой адрес и чужая служба — вопрос.
func TestAdmittedAddressAsksNoQuestion(t *testing.T) {
	old := admitAddrs
	t.Cleanup(func() { admitAddrs = old })
	admitAddrs = func([]netip.Addr, time.Duration) error { return nil }
	resetAdmittedForTest(t)
	a := &Agent{managed: true, mode: "learn", hostID: "h"}
	a.rules = []pol.Rule{{ID: "park-svc-update", Enabled: true, Action: "allow",
		Match: pol.Match{Direction: "out", Protocol: "tcp", RemotePort: 443, OnDemand: []string{"api.github.com"},
			Bindings: []pol.Binding{{Name: "nmserver", Cgroup: "system.slice/nmserver.service"}}}}}
	svc := pol.Contact{Host: "h", Direction: "out", Protocol: "tcp", RemoteIP: "140.82.121.6", RemotePort: 443, Cgroup: "system.slice/nmserver.service"}
	if !a.questionLocked(svc) {
		t.Fatal("not admitted yet: must ask")
	}
	if err := admitCommand(`{"ips":["140.82.121.6"],"ttl_ms":3600000}`); err != nil {
		t.Fatal(err)
	}
	if a.questionLocked(svc) {
		t.Fatal("admitted service address raised a question")
	}
	stranger := svc
	stranger.Cgroup = "user.slice/curl"
	if !a.questionLocked(stranger) {
		t.Fatal("another program to the same address must ask")
	}
	other := svc
	other.RemoteIP = "198.51.100.9"
	if !a.questionLocked(other) {
		t.Fatal("address outside the set must ask")
	}
}

func resetAdmittedForTest(t *testing.T) {
	t.Helper()
	svcAdmitted.Lock()
	prev := svcAdmitted.until
	svcAdmitted.until = map[netip.Addr]int64{}
	svcAdmitted.Unlock()
	t.Cleanup(func() { svcAdmitted.Lock(); svcAdmitted.until = prev; svcAdmitted.Unlock() })
}

func TestLocalAdmissionReportedBeforeDownloadAndRetried(t *testing.T) {
	resetAdmittedForTest(t)
	a, _, reports, _ := agentFixture(t)
	prev := admitAddrs
	t.Cleanup(func() { admitAddrs = prev })
	ip := netip.MustParseAddr("203.0.113.77")
	admitAddrs = func([]netip.Addr, time.Duration) error { return errors.New("nft failed") }
	if err := a.admitLocal(context.Background(), []netip.Addr{ip}); err == nil {
		t.Fatal("failed filter accepted")
	}
	if len(*reports) != 0 || len(admittedNow(store.NowMS())) != 0 {
		t.Fatal("failed admission reported")
	}
	admitAddrs = func([]netip.Addr, time.Duration) error { return nil }
	if err := a.admitLocal(context.Background(), []netip.Addr{ip}); err != nil {
		t.Fatal(err)
	}
	first := (*reports)[0].ServiceAdmitted
	if len(first) != 1 || first[0].IP != ip.String() || first[0].UntilMS <= store.NowMS() {
		t.Fatalf("missing admission: %+v", first)
	}
	if _, err := a.exchangePoll(protocol.PollReq{Rev: -1}); err != nil {
		t.Fatal(err)
	}
	again := (*reports)[1].ServiceAdmitted
	if len(again) != 1 || again[0] != first[0] {
		t.Fatalf("retry changed expiry: %+v -> %+v", first, again)
	}
	svcAdmitted.Lock()
	svcAdmitted.until[ip] = store.NowMS() - 1
	svcAdmitted.Unlock()
	if _, err := a.exchangePoll(protocol.PollReq{Rev: -1}); err != nil {
		t.Fatal(err)
	}
	if len((*reports)[2].ServiceAdmitted) != 0 {
		t.Fatal("expired admission reported")
	}
}
