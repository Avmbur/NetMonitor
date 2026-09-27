package collect

import (
	"encoding/hex"
	"testing"
)

func TestParseDNSAnswersA(t *testing.T) {
	raw, err := hex.DecodeString("000181800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c0004c000022a")
	if err != nil {
		t.Fatal(err)
	}
	recs := ParseDNSAnswers(raw)
	if len(recs) != 1 {
		t.Fatalf("n=%d %+v", len(recs), recs)
	}
	if recs[0].Name != "example.com" || recs[0].IP != "192.0.2.42" {
		t.Fatalf("%+v", recs[0])
	}
}

func TestPTRIPFromReverseName(t *testing.T) {
	if g := ptrIP("42.2.0.192.in-addr.arpa"); g != "192.0.2.42" {
		t.Fatal(g)
	}
	if ptrIP("example.com") != "" {
		t.Fatal("forward name")
	}
	if g := ptrIP("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"); g != "fe80:0:0:0:0:0:0:1" {
		t.Fatal(g)
	}
}
