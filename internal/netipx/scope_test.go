package netipx

import (
	"net/netip"
	"testing"
)

func TestScopeOwnOverlayLanInternet(t *testing.T) {
	own := []netip.Prefix{MustPrefix("192.168.10.181/32")}
	overlay := []netip.Prefix{MustPrefix("10.8.0.0/24")}
	lan := DefaultLAN()
	if g := Scope(netip.MustParseAddr("192.168.10.181"), lan, overlay, own); g != "own" {
		t.Fatal(g)
	}
	if g := Scope(netip.MustParseAddr("10.8.0.9"), lan, overlay, own); g != "overlay" {
		t.Fatal(g)
	}
	if g := Scope(netip.MustParseAddr("192.168.1.1"), lan, overlay, own); g != "lan" {
		t.Fatal(g)
	}
	if g := Scope(netip.MustParseAddr("1.1.1.1"), lan, overlay, own); g != "internet" {
		t.Fatal(g)
	}
}
