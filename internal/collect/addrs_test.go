package collect

import "testing"

func TestIsDockerBridge(t *testing.T) {
	ok := []string{"docker0", "br-0123456789ab", "BR-AABBCCDDEEFF"}
	no := []string{"br-lan", "br-ext", "br-abc", "veth0", "cni0", "docker1", ""}
	for _, n := range ok {
		if !IsDockerBridge(n) {
			t.Fatal("want bridge", n)
		}
	}
	for _, n := range no {
		if IsDockerBridge(n) {
			t.Fatal("not a docker bridge", n)
		}
	}
}
