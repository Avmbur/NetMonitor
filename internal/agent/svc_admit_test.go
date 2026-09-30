package agent

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"netmonitor/internal/protocol"
	"netmonitor/internal/svcnet"
)

func TestMonitorAdmitIsAckedOnlyAfterFilterAccepts(t *testing.T) {
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
