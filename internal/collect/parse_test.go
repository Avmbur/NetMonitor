package collect

import "testing"

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
