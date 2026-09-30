package collect

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
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

func dnsLabel(name string) []byte {
	var b []byte
	for _, p := range strings.Split(name, ".") {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

func dnsQuestion(name string) []byte {
	return append(dnsLabel(name), 0, 1, 0, 1)
}

func dnsRR(name string, typ uint16, rdata []byte) []byte {
	b := dnsLabel(name)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[4:8], 60)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	b = append(b, hdr[:]...)
	return append(b, rdata...)
}

func dnsResp(qd, an, ns, ar int, body []byte) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[2:4], 0x8180)
	binary.BigEndian.PutUint16(h[4:6], uint16(qd))
	binary.BigEndian.PutUint16(h[6:8], uint16(an))
	binary.BigEndian.PutUint16(h[8:10], uint16(ns))
	binary.BigEndian.PutUint16(h[10:12], uint16(ar))
	return append(h, body...)
}

func TestParseDNSAnswersCNAMEKeepsEveryAddress(t *testing.T) {
	body := append(dnsQuestion("example.com"), dnsRR("example.com", 5, dnsLabel("mid.example.net"))...)
	body = append(body, dnsRR("mid.example.net", 5, dnsLabel("cdn.example.net"))...)
	body = append(body, dnsRR("cdn.example.net", 1, []byte{192, 0, 2, 5})...)
	body = append(body, dnsRR("cdn.example.net", 1, []byte{192, 0, 2, 6})...)
	body = append(body, dnsRR("cdn.example.net", 1, []byte{192, 0, 2, 7})...)
	body = append(body, dnsRR("ns.example.net", 1, []byte{192, 0, 2, 9})...)
	// answers: two CNAMEs and two A; additional: one A of the target and unrelated glue
	pkt := dnsResp(1, 4, 0, 2, body)
	recs := ParseDNSAnswers(pkt)
	got := map[string]bool{}
	for _, r := range recs {
		got[r.Name+" "+r.IP+" "+r.Kind] = true
	}
	for _, name := range []string{"example.com", "mid.example.net", "cdn.example.net"} {
		for _, ip := range []string{"192.0.2.5", "192.0.2.6", "192.0.2.7"} {
			if !got[name+" "+ip+" a"] {
				t.Fatalf("missing %s %s in %+v", name, ip, recs)
			}
		}
	}
	if got["ns.example.net 192.0.2.9 a"] {
		t.Fatal("glue attached", recs)
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
