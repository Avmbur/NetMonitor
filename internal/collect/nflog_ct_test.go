//go:build linux

package collect

import (
	"encoding/binary"
	"testing"
)

func nla(typ uint16, payload []byte) []byte {
	n := 4 + len(payload)
	b := make([]byte, (n+3)&^3)
	binary.LittleEndian.PutUint16(b[0:2], uint16(n))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], payload)
	return b
}

func TestCTFromNFULABareAttributes(t *testing.T) {
	ip := append(nla(ctaIPv4Src, []byte{203, 0, 113, 8}), nla(ctaIPv4Dst, []byte{192, 168, 10, 186})...)
	sport := make([]byte, 2)
	dport := make([]byte, 2)
	binary.BigEndian.PutUint16(sport, 40000)
	binary.BigEndian.PutUint16(dport, 8080)
	proto := append(append(nla(ctaProtoNum, []byte{6}), nla(ctaProtoSrcPort, sport)...), nla(ctaProtoDstPort, dport)...)
	tuple := append(nla(ctaTupleIP|nlaFNested, ip), nla(ctaTupleProto|nlaFNested, proto)...)
	body := nla(ctaTupleOrig|nlaFNested, tuple)
	e, ok := ctFromNFULA(body)
	if !ok || e.OrigDst.String() != "192.168.10.186" || e.OrigDport == nil || *e.OrigDport != 8080 {
		t.Fatalf("%v %+v", ok, e)
	}
}

func TestCTFromNFULAPortlessICMP(t *testing.T) {
	ip := append(nla(ctaIPv4Src, []byte{172, 17, 0, 2}), nla(ctaIPv4Dst, []byte{203, 0, 113, 50})...)
	tuple := append(nla(ctaTupleIP|nlaFNested, ip), nla(ctaTupleProto|nlaFNested, nla(ctaProtoNum, []byte{1}))...)
	body := nla(ctaTupleOrig|nlaFNested, tuple)
	e, ok := ctFromNFULA(body)
	if !ok || e.Protocol != "icmp" || e.OrigSrc.String() != "172.17.0.2" || e.OrigDport != nil {
		t.Fatalf("%v %+v", ok, e)
	}
}
