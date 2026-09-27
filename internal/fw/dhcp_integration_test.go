//go:build linux

package fw

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestActualDHCPRenewal(t *testing.T) {
	if os.Getenv("NM_FW_NETNS_TEST") != "1" || os.Getenv("NM_DHCP_SERVER") == "" {
		t.Skip("isolated netns; dnsmasq and busybox required")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, out)
		}
		return string(out)
	}
	peer := exec.Command("unshare", "-n", "sleep", "90")
	if e := peer.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	pid := strconv.Itoa(peer.Process.Pid)
	own, _ := os.Readlink("/proc/self/ns/net")
	for i := 0; i < 300; i++ {
		ns, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if ns != "" && ns != own {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "d26local", "type", "veth", "peer", "name", "d26peer")
	run("ip", "link", "set", "d26peer", "netns", pid)
	run("ip", "addr", "add", "198.18.26.1/24", "dev", "d26local")
	run("ip", "-6", "addr", "add", "fd00:d26::1/64", "dev", "d26local", "nodad")
	run("ip", "link", "set", "d26local", "up")
	ns := func(args ...string) string { return run("nsenter", append([]string{"-t", pid, "-n"}, args...)...) }
	ns("ip", "link", "set", "lo", "up")
	ns("ip", "addr", "add", "198.18.26.2/24", "dev", "d26peer")
	ns("ip", "-6", "addr", "add", "fd00:d26::2/64", "dev", "d26peer", "nodad")
	ns("ip", "link", "set", "d26peer", "up")

	dir := t.TempDir()
	serverLog := filepath.Join(dir, "server.log")
	dns := exec.Command("nsenter", "-t", pid, "-n", os.Getenv("NM_DHCP_SERVER"),
		"--keep-in-foreground", "--conf-file=/dev/null", "--port=0", "--user=root", "--interface=d26peer", "--bind-interfaces",
		"--dhcp-range=198.18.26.10,198.18.26.20,255.255.255.0,2m",
		"--dhcp-range=fd00:d26::10,fd00:d26::20,64,2m", "--enable-ra",
		"--dhcp-leasefile="+filepath.Join(dir, "leases"), "--pid-file="+filepath.Join(dir, "dns.pid"),
		"--log-dhcp", "--log-facility="+serverLog)
	dns.Stderr = os.Stderr
	time.Sleep(1200 * time.Millisecond) // IPv6 link-local duplicate-address detection.
	if err := dns.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { dns.Process.Kill(); dns.Wait() }()
	c := NewController()
	if err := c.Apply(Policy{Mode: "learn"}); err != nil {
		t.Fatal(err)
	}
	type client struct {
		cmd         *exec.Cmd
		events, log string
	}
	clients := []client{}
	for _, version := range []string{"4", "6"} {
		events := filepath.Join(dir, "events"+version)
		script := filepath.Join(dir, "hook"+version)
		body := "#!/bin/sh\nset -eu\ncase \"$1\" in bound|renew)\n"
		if version == "4" {
			body += "ip addr replace \"$ip/24\" dev \"$interface\"\n"
		}
		body += "printf '%s\\n' \"$1\" >> '" + events + "'\n;; esac\n"
		if err := os.WriteFile(script, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		name := "udhcpc"
		if version == "6" {
			name = "udhcpc6"
		}
		path := filepath.Join(dir, "client"+version+".log")
		log, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		cmd := exec.Command("busybox", name, "-f", "-i", "d26local", "-s", script, "-p", filepath.Join(dir, "pid"+version), "-t", "5", "-T", "1", "-n")
		cmd.Stdout = log
		cmd.Stderr = log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		clients = append(clients, client{cmd, events, path})
	}
	wait := func(want int) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			ready := true
			for _, cl := range clients {
				b, _ := os.ReadFile(cl.events)
				if len(strings.Fields(string(b))) < want {
					ready = false
				}
			}
			if ready {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		for _, cl := range clients {
			b, _ := os.ReadFile(cl.log)
			t.Log(string(b))
		}
		b, _ := os.ReadFile(serverLog)
		t.Log(string(b))
		t.Fatal("DHCP client failed to bind/renew")
	}
	wait(1)
	for _, mode := range []string{"learn", "block"} {
		if err := c.Apply(Policy{Mode: mode}); err != nil {
			t.Fatal(err)
		}
		for _, cl := range clients {
			if err := cl.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatal(err)
			}
		}
		want := 2
		if mode == "block" {
			want = 3
		}
		wait(want)
	}
	leases, err := os.ReadFile(filepath.Join(dir, "leases"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(leases), "198.18.26.") || !strings.Contains(string(leases), "fd00:d26::") {
		t.Fatal("missing real leases", string(leases))
	}
	log, _ := os.ReadFile(serverLog)
	if !strings.Contains(string(log), "DHCPRENEW") {
		t.Fatal("IPv6 renewal not observed", string(log))
	}
	t.Log("BusyBox DHCPv4/v6 acquired leases from dnsmasq and renewed in learn and block modes")
}
