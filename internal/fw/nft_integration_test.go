//go:build linux

package fw

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNFTKernelAtomicity(t *testing.T) {
	if os.Getenv("NM_FW_NETNS_TEST") != "1" {
		t.Skip("run as root inside a disposable network namespace")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
		return string(out)
	}
	peer := exec.Command("unshare", "-n", "sleep", "120")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Process.Kill(); _ = peer.Wait() }()
	pid := strconv.Itoa(peer.Process.Pid)
	// Wait until unshare has actually switched the child's namespace.
	ownNS, _ := os.Readlink("/proc/self/ns/net")
	deadline := time.Now().Add(3 * time.Second)
	for {
		ns, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if ns != "" && ns != ownNS {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer netns not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "d33local", "type", "veth", "peer", "name", "d33peer")
	run("ip", "link", "set", "d33peer", "netns", pid)
	run("ip", "addr", "add", "198.18.0.1/24", "dev", "d33local")
	run("ip", "-6", "addr", "add", "fd00:d33::1/64", "dev", "d33local", "nodad")
	run("ip", "link", "set", "d33local", "up")
	ns := func(args ...string) string { return run("nsenter", append([]string{"-t", pid, "-n"}, args...)...) }
	ns("ip", "link", "set", "lo", "up")
	ns("ip", "addr", "add", "198.18.0.2/24", "dev", "d33peer")
	ns("ip", "-6", "addr", "add", "fd00:d33::2/64", "dev", "d33peer", "nodad")
	ns("ip", "link", "set", "d33peer", "up")
	// External firewall must survive every operation and failed transaction.
	run("nft", "add", "table", "inet", "foreign_d33")
	run("nft", "add", "chain", "inet", "foreign_d33", "sentinel")
	run("nft", "add", "rule", "inet", "foreign_d33", "sentinel", "counter")
	foreign := run("nft", "list", "table", "inet", "foreign_d33")
	ping := func(ip string, want bool) {
		t.Helper()
		out, err := exec.Command("ping", "-n", "-c", "1", "-W", "1", ip).CombinedOutput()
		if (err == nil) != want {
			t.Fatalf("ping %s want=%v: %v %s", ip, want, err, out)
		}
	}
	v4 := "198.18.0.2"
	v6 := "fd00:d33::2"
	ping(v4, true)
	ping(v6, true)
	c := NewController()
	p := Policy{Mode: "allow", Blocks: []Desired{{IP: netip.MustParseAddr(v4)}, {IP: netip.MustParseAddr(v6)}}}
	if err := c.Apply(p); err != nil {
		t.Fatal(err)
	}
	ping(v4, false)
	ping(v6, false)
	before := run("nft", "list", "table", "inet", "netmon")
	if err := c.Apply(p); err != nil {
		t.Fatal("repeat", err)
	}
	if got := run("nft", "list", "table", "inet", "netmon"); got != before {
		t.Fatal("duplicate command changed policy")
	}
	for _, failure := range []string{"syntax", "permission", "missing"} {
		t.Run(failure, func(t *testing.T) {
			broken := *c
			broken.execute = func(input, name string, args ...string) ([]byte, error) {
				switch failure {
				case "syntax":
					return command(input+"add rule inet netmon input invalid_expression\n", name, args...)
				case "missing":
					return command(input, "/nonexistent-nm-nft", args...)
				default:
					cmd := exec.Command(name, args...)
					cmd.Stdin = strings.NewReader(input)
					cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
					out, err := cmd.CombinedOutput()
					if err == nil {
						return out, nil
					}
					return out, fmt.Errorf("nft denied: %w: %s", err, out)
				}
			}
			if err := broken.Apply(Policy{Mode: "allow"}); err == nil {
				t.Fatal("failed backend reported success")
			}
			if got := run("nft", "list", "table", "inet", "netmon"); got != before {
				t.Fatal("failure changed old firewall")
			}
			ping(v4, false)
			ping(v6, false)
		})
	}
	if err := c.Apply(Policy{Mode: "allow"}); err != nil {
		t.Fatal("recovery", err)
	}
	ping(v4, true)
	ping(v6, true)
	if got := run("nft", "list", "table", "inet", "foreign_d33"); got != foreign {
		t.Fatal("foreign firewall changed")
	}
	// Strict-mode batch must be valid in the actual kernel, with IPv6 too.
	strict := Policy{Mode: "learn", Monitor: netip.MustParseAddr(v6), BlockNets: []netip.Prefix{netip.MustParsePrefix("fd00:d33::/64")}}
	if err := c.Apply(strict); err != nil {
		t.Fatal("strict mode", err)
	}
	ping(v6, true) // Never-block wins even over a containing group block.
	ping(v4, false)
	hits := LearnHits()
	found := false
	for _, h := range hits {
		if h.IP.String() == v4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("learning stopped recording attempts: %+v", hits)
	}
	if err := c.Apply(strict); err != nil {
		t.Fatal(err)
	}
	if len(LearnHits()) == 0 {
		t.Fatal("refresh erased learn set")
	}
	// Expiry is absolute and remains expired on a later rebuild.
	exp := time.Now().Add(400 * time.Millisecond).UnixMilli()
	expiry := Policy{Mode: "allow", Blocks: []Desired{{IP: netip.MustParseAddr(v4), ExpiresAtMS: exp}}}
	if err := c.Apply(expiry); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := c.Apply(expiry); err != nil {
		t.Fatal(err)
	}
	ping(v4, true)
	if out := run("nft", "list", "set", "inet", "netmon", "ban4"); bytes.Contains([]byte(out), []byte(v4)) {
		t.Fatal("expired ban resurrected")
	}
	run("nft", "delete", "table", "inet", "netmon")
	if c.Alive() {
		t.Fatal("missing table reported alive")
	}
	if err := c.Apply(p); err != nil {
		t.Fatal("restore", err)
	}
	ping(v4, false)
	ping(v6, false)
	// Damage is detected within the owned table, without touching foreign rules.
	for _, damage := range []string{
		"flush chain inet netmon input",
		"delete chain inet netmon output",
		"flush set inet netmon ban4",
		"delete set inet netmon learn4i",
	} {
		if !c.Alive() {
			t.Fatal("whole policy not recognized before damage")
		}
		run("nft", strings.Fields(damage)...)
		if c.Alive() {
			t.Fatal("damage undetected", damage)
		}
		if err := c.Apply(p); err != nil {
			t.Fatal("repair", damage, err)
		}
		ping(v4, false)
		ping(v6, false)
	}
	t.Log("IPv4/IPv6 packets; duplicate apply; invalid rule, permission, missing binary; recovery; protected prefix; learning; TTL; foreign table: OK")
	// The same packet fixture also verifies the legacy fallback. Remove only our
	// nft table: two independent backends must not mask each other's failures.
	run("nft", "delete", "table", "inet", "netmon")
	legacy := &Controller{backend: "iptables", execute: command}
	if err := legacy.Apply(p); err != nil {
		t.Fatal("fallback", err)
	}
	ping(v4, false)
	ping(v6, false)
	stable := run("ipset", "save", activeSet)
	for _, failure := range []string{"set-fill", "ipv6-hook", "switch"} {
		t.Run("iptables-"+failure, func(t *testing.T) {
			broken := *legacy
			broken.execute = func(input, name string, args ...string) ([]byte, error) {
				if name == "ipset" && len(args) > 0 && args[0] == "restore" && failure == "set-fill" {
					return command(input+"invalid command\n", name, args...)
				}
				if name == "ip6tables-restore" && failure == "ipv6-hook" {
					return nil, fmt.Errorf("injected permission denied")
				}
				if name == "ipset" && len(args) > 0 && args[0] == "swap" && failure == "switch" {
					return nil, fmt.Errorf("injected swap failure")
				}
				return command(input, name, args...)
			}
			if err := broken.Apply(Policy{Mode: "allow"}); err == nil {
				t.Fatal("failed fallback reported success")
			}
			if got := run("ipset", "save", activeSet); got != stable {
				t.Fatal("failed fallback replaced active generation")
			}
			ping(v4, false)
			ping(v6, false)
		})
	}
	if err := legacy.Apply(Policy{Mode: "learn"}); err == nil {
		t.Fatal("unsupported strict mode silently enabled")
	}
	ping(v4, false)
	ping(v6, false)
	if err := legacy.Apply(Policy{Mode: "allow", BlockNets: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/24"), netip.MustParsePrefix("fd00:d33::/64")}, Never: []netip.Prefix{netip.MustParsePrefix("198.18.0.2/32")}, Monitor: netip.MustParseAddr(v6)}); err != nil {
		t.Fatal(err)
	}
	ping(v4, true)
	ping(v6, true)
	if err := legacy.Apply(Policy{Mode: "allow", Blocks: []Desired{{IP: netip.MustParseAddr(v4), ExpiresAtMS: time.Now().Add(1800 * time.Millisecond).UnixMilli()}}}); err != nil {
		t.Fatal(err)
	}
	ping(v4, false)
	time.Sleep(900 * time.Millisecond)
	ping(v4, true)
	if !legacy.Alive() {
		t.Fatal("fallback not alive")
	}
	if got := run("nft", "list", "table", "inet", "foreign_d33"); got != foreign {
		t.Fatal("fallback changed foreign nft table")
	}
	t.Log("fallback IPv4/IPv6, atomic generation, failures, never-block, strict refusal and TTL: OK")

}

func TestUFWReload(t *testing.T) {
	if os.Getenv("NM_FW_UFW_TEST") != "1" {
		t.Skip("requires private mount/net namespace and copied ufw directories")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		return string(out)
	}
	run("ip", "link", "set", "lo", "up")
	run("ufw", "default", "allow", "incoming")
	run("ufw", "default", "allow", "outgoing")
	run("ufw", "--force", "enable")
	defer exec.Command("ufw", "--force", "disable").Run()
	if !strings.Contains(run("ufw", "status"), "Status: active") {
		t.Fatal("ufw did not start")
	}
	c := NewController()
	p := Policy{Mode: "allow", Blocks: []Desired{{BlockID: "reload", IP: netip.MustParseAddr("198.18.11.7")}}}
	if err := c.Apply(p); err != nil {
		t.Fatal(err)
	}
	run("ufw", "reload")
	snapshot := func() string {
		var lines []string
		for _, line := range strings.Split(run("iptables-save"), "\n") {
			if !strings.HasPrefix(line, "#") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}
	foreign := snapshot()
	if !strings.Contains(foreign, "ufw-") {
		t.Fatal("no ufw rules")
	}
	if err := c.Apply(p); err != nil {
		t.Fatal(err)
	}
	if !c.Alive() {
		t.Fatal("policy not intact after ufw reload")
	}
	if snapshot() != foreign {
		t.Fatal("repair changed ufw rules")
	}
	// Model another firewall replacing the owned table while leaving its own rules.
	run("nft", "delete", "table", "inet", "netmon")
	if c.Alive() {
		t.Fatal("deleted table alive")
	}
	if err := c.Apply(p); err != nil {
		t.Fatal(err)
	}
	if !c.Alive() || !strings.Contains(run("nft", "list", "set", "inet", "netmon", "ban4"), "198.18.11.7") {
		t.Fatal("ban not recovered")
	}
	if snapshot() != foreign {
		t.Fatal("recovery changed ufw")
	}
	t.Log("active UFW reload and own-table recovery preserve foreign rules")
}
