package policy

import "testing"

func TestExpandStarterSSH(t *testing.T) {
	base := Rule{ID: StarterSSH, Enabled: true, Action: "allow", Match: Match{Direction: "in", Protocol: "tcp", LocalPort: 22}}
	dns := Rule{ID: "default-dns-udp", Enabled: true, Action: "allow", Match: Match{Direction: "out", Protocol: "udp", RemotePort: 53}}
	out := ExpandStarterSSH([]Rule{base, dns}, []int{22, 2222})
	if len(out) != 3 || out[0].Match.LocalPort != 22 || out[1].ID != StarterSSH+"-2222" || out[1].Match.LocalPort != 2222 || out[2].ID != dns.ID {
		t.Fatal(out)
	}
	if again := ExpandStarterSSH(out, []int{2222}); len(again) != 3 {
		t.Fatal("expanded twice", again)
	}
	moved := base
	moved.Match.LocalPort = 2200
	if out := ExpandStarterSSH([]Rule{moved}, []int{2222}); len(out) != 1 || out[0].Match.LocalPort != 2200 {
		t.Fatal("hand-moved starter touched", out)
	}
}
