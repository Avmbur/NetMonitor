package collect

import (
	"net"
	"net/netip"
	"testing"
)

func TestParseEstablishedAcct(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.10.180 dst=1.1.1.1 sport=44552 dport=443 packets=10 bytes=1234 src=1.1.1.1 dst=192.168.10.180 sport=443 dport=44552 packets=8 bytes=900 [ASSURED] mark=0 zone=0 use=2"
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("parse")
	}
	if e.Protocol != "tcp" || e.State != "ESTABLISHED" {
		t.Fatalf("%s %s", e.Protocol, e.State)
	}
	if e.OrigSrc.String() != "192.168.10.180" || e.OrigDst.String() != "1.1.1.1" {
		t.Fatalf("orig %s %s", e.OrigSrc, e.OrigDst)
	}
	if e.OrigPackets != 10 || e.OrigBytes != 1234 || e.ReplyPackets != 8 || e.ReplyBytes != 900 {
		t.Fatalf("acct %d %d %d %d", e.OrigPackets, e.OrigBytes, e.ReplyPackets, e.ReplyBytes)
	}
	if e.OrigDport == nil || *e.OrigDport != 443 {
		t.Fatal("dport")
	}
	if e.Unreplied || !e.Assured {
		t.Fatal("flags")
	}
}

func TestClassifyDockerBridge(t *testing.T) {
	net := netip.MustParsePrefix("172.17.0.0/16")
	box := netip.MustParseAddr("192.168.10.186")
	c1, c2 := netip.MustParseAddr("172.17.0.2"), netip.MustParseAddr("172.17.0.3")
	out := netip.MustParseAddr("1.1.1.1")
	sp, dp := 40000, 443
	e := Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: out, OrigSport: &sp, OrigDport: &dp}
	dir, local, remote, _, rport := ClassifyNets(e, []netip.Addr{box}, []netip.Prefix{net})
	if dir != "out" || local != c1.String() || remote != out.String() || rport == nil || *rport != 443 {
		t.Fatalf("out %s %s %s %v", dir, local, remote, rport)
	}
	e = Entry{Protocol: "tcp", OrigSrc: out, OrigDst: box, OrigSport: &sp, OrigDport: &dp}
	dir, _, _, lport, _ := ClassifyNets(e, []netip.Addr{box}, []netip.Prefix{net})
	if dir != "in" || lport == nil || *lport != 443 {
		t.Fatalf("published %s %v", dir, lport)
	}
	e = Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: c2, OrigSport: &sp, OrigDport: &dp}
	dir, _, _, _, _ = ClassifyNets(e, []netip.Addr{box}, []netip.Prefix{net})
	if dir != "bridge" {
		t.Fatal(dir)
	}
	// Контейнер → хост и хост → контейнер различаются: в карантине режется только первое.
	gw := netip.MustParseAddr("172.17.0.1")
	locals := []netip.Addr{box, gw}
	e = Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: box, OrigSport: &sp, OrigDport: &dp}
	if dir, _, _, _, _ = ClassifyNets(e, locals, []netip.Prefix{net}); dir != "tohost" {
		t.Fatal("container to host", dir)
	}
	e = Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: gw, OrigSport: &sp, OrigDport: &dp}
	if dir, _, _, _, _ = ClassifyNets(e, locals, []netip.Prefix{net}); dir != "tohost" {
		t.Fatal("container to gateway", dir)
	}
	e = Entry{Protocol: "tcp", OrigSrc: box, OrigDst: c1, OrigSport: &sp, OrigDport: &dp}
	if dir, _, _, _, _ = ClassifyNets(e, locals, []netip.Prefix{net}); dir != "fromhost" {
		t.Fatal("host to container", dir)
	}
	// Мост хоста наружу — обычный исход хоста.
	e = Entry{Protocol: "tcp", OrigSrc: gw, OrigDst: out, OrigSport: &sp, OrigDport: &dp}
	if dir, _, _, _, _ = ClassifyNets(e, []netip.Addr{box, gw}, []netip.Prefix{net}); dir != "out" {
		t.Fatal("host bridge address out", dir)
	}
}

func TestContainerSessionIgnoresHostListeners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	sp := ln.Addr().(*net.TCPAddr).Port
	dp := 443
	c1 := netip.MustParseAddr("172.17.0.2")
	e := Entry{Protocol: "tcp", OrigSrc: c1, OrigDst: netip.MustParseAddr("1.1.1.1"), OrigSport: &sp, OrigDport: &dp}
	dir, _, _, _, _ := ClassifySessionNets(e, []netip.Addr{netip.MustParseAddr("192.168.10.186")}, []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")})
	if dir != "out" {
		t.Fatal("container source port matched a host listener:", dir)
	}
}

func TestTCPReplyIsNotABareSYN(t *testing.T) {
	syn := Entry{Protocol: "tcp", TCPFlagsKnown: true, TCPFlags: 0x02}
	if syn.TCPReply() {
		t.Fatal("bare SYN is a new session")
	}
	for _, flags := range []int{0x10, 0x12, 0x18} {
		e := Entry{Protocol: "tcp", TCPFlagsKnown: true, TCPFlags: flags}
		if !e.TCPReply() {
			t.Fatalf("flags %x", flags)
		}
	}
	if (Entry{Protocol: "tcp"}).TCPReply() || (Entry{Protocol: "udp", TCPFlagsKnown: true, TCPFlags: 0x10}).TCPReply() {
		t.Fatal("missing flags or udp")
	}
}

func TestParseUnreplied(t *testing.T) {
	line := "ipv4     2 tcp      6 59 SYN_SENT src=10.0.0.2 dst=8.8.8.8 sport=1 dport=53 [UNREPLIED] src=8.8.8.8 dst=10.0.0.2 sport=53 dport=1 mark=0 zone=0 use=1"
	e, ok := ParseLine(line)
	if !ok {
		t.Fatal("parse")
	}
	if !e.Unreplied || e.State != "SYN_SENT" {
		t.Fatalf("%v %s", e.Unreplied, e.State)
	}
}

func TestNFLogCTDirection(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          []byte
		known, reply bool
	}{
		{"established", []byte{0, 0, 0, 0}, true, false},
		{"related", []byte{0, 0, 0, 1}, true, false},
		{"new", []byte{0, 0, 0, 2}, true, false},
		{"established_reply", []byte{0, 0, 0, 3}, true, true},
		{"related_reply", []byte{0, 0, 0, 4}, true, true},
		{"missing", nil, false, false},
		{"truncated", []byte{0, 0, 3}, false, false},
		{"unknown", []byte{0, 0, 0, 5}, false, false},
		{"wrong_byte_order", []byte{3, 0, 0, 0}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := Entry{CTDirectionKnown: true, CTReply: true}
			e.setNFLogCTInfo(tc.raw)
			if e.CTDirectionKnown != tc.known || e.CTReply != tc.reply {
				t.Fatalf("direction known=%v reply=%v", e.CTDirectionKnown, e.CTReply)
			}
		})
	}
}
