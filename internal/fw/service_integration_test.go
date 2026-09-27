//go:build linux

package fw

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServicePeer(t *testing.T) {
	if os.Getenv("NM_SERVICE_PEER") != "1" {
		t.Skip("service fixture")
	}
	for _, address := range []string{"0.0.0.0:67", "[::]:547", "0.0.0.0:53", "[::]:53", "0.0.0.0:123", "[::]:123", "0.0.0.0:18080", "[::]:18080"} {
		network := "udp4"
		if strings.HasPrefix(address, "[") {
			network = "udp6"
		}
		addr, e := net.ResolveUDPAddr(network, address)
		if e != nil {
			t.Fatal(e)
		}
		sock, e := net.ListenUDP(network, addr)
		if e != nil {
			t.Fatal(e)
		}
		defer sock.Close()
		go func() {
			buf := make([]byte, 2048)
			for {
				n, peer, e := sock.ReadFromUDP(buf)
				if e != nil {
					return
				}
				_, _ = sock.WriteToUDP(buf[:n], peer)
			}
		}()
	}
	for _, address := range []string{"0.0.0.0:53", "[::]:53", "0.0.0.0:18080", "[::]:18080"} {
		network := "tcp4"
		if strings.HasPrefix(address, "[") {
			network = "tcp6"
		}
		sock, e := net.Listen(network, address)
		if e != nil {
			t.Fatal(e)
		}
		defer sock.Close()
		go func() {
			for {
				conn, e := sock.Accept()
				if e != nil {
					return
				}
				go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
			}
		}()
	}
	fmt.Println("READY")
	time.Sleep(50 * time.Second)
}
func TestStrictServiceTraffic(t *testing.T) {
	if os.Getenv("NM_FW_NETNS_TEST") != "1" {
		t.Skip("root in disposable netns")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, out)
		}
		return string(out)
	}
	peer := exec.Command("unshare", "-n", "sleep", "100")
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
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	services := exec.Command("nsenter", "-t", pid, "-n", "env", "NM_SERVICE_PEER=1", exe, "-test.run=^TestServicePeer$")
	out, e := services.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	services.Stderr = os.Stderr
	if e = services.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { services.Process.Kill(); services.Wait() }()
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatal("peer services not ready")
	}
	// The preceding fixture can leave legacy hooks. They are owned only by tests.
	for _, tool := range []string{"iptables", "ip6tables"} {
		exec.Command(tool, "-D", "INPUT", "-j", "NM_IN").Run()
		exec.Command(tool, "-D", "OUTPUT", "-j", "NM_OUT").Run()
	}
	c := NewController()
	for _, mode := range []string{"learn", "block"} {
		if e = c.Apply(Policy{Mode: mode}); e != nil {
			t.Fatal(e)
		}
		run("ip", "-6", "neigh", "flush", "dev", "d26local")
		for _, family := range []string{"4", "6"} {
			local, remote := "198.18.26.1", "198.18.26.2"
			if family == "6" {
				local, remote = "fd00:d26::1", "fd00:d26::2"
			}
			for _, port := range []int{53, 123, 67, 547, 18080} {
				if family == "4" && port == 547 || family == "6" && port == 67 {
					continue
				}
				lp := 0
				if port == 67 {
					lp = 68
				}
				if port == 547 {
					lp = 546
				}
				conn, e := net.DialUDP("udp"+family, &net.UDPAddr{IP: net.ParseIP(local), Port: lp}, &net.UDPAddr{IP: net.ParseIP(remote), Port: port})
				if e != nil {
					t.Fatal(e)
				}
				conn.SetDeadline(time.Now().Add(600 * time.Millisecond))
				payload := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
				if port == 67 {
					payload = make([]byte, 244)
					payload[0] = 1
					copy(payload[236:], []byte{99, 130, 83, 99, 53, 1, 3, 255})
				}
				if port == 547 {
					payload = []byte{5, 1, 2, 3}
				}
				_, e = conn.Write(payload)
				buf := make([]byte, 2048)
				n, re := conn.Read(buf)
				conn.Close()
				want := port != 18080
				if want && (e != nil || re != nil || !bytes.Equal(payload, buf[:n])) {
					t.Fatalf("%s UDP%s port%d: write=%v read=%v", mode, family, port, e, re)
				}
				if !want && re == nil {
					t.Fatal("unknown UDP passed strict policy")
				}
			}
			for _, port := range []int{53, 18080} {
				conn, e := net.DialTimeout("tcp"+family, net.JoinHostPort(remote, strconv.Itoa(port)), 600*time.Millisecond)
				if port == 18080 {
					if e == nil {
						conn.Close()
						t.Fatal("unknown TCP passed strict policy")
					}
					continue
				}
				if e != nil {
					t.Fatal("TCP DNS blocked", e)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				packet := []byte{0, 2, 0x12, 0x34}
				conn.Write(packet)
				buf := make([]byte, 4)
				_, e = io.ReadFull(conn, buf)
				conn.Close()
				if e != nil || !bytes.Equal(buf, packet) {
					t.Fatal("TCP DNS exchange failed", e)
				}
			}
		}
		if got := run("ip", "-6", "neigh", "show", "dev", "d26local"); !strings.Contains(got, "fd00:d26::2") || strings.Contains(got, "FAILED") {
			t.Fatal("neighbor discovery failed", got)
		}
	}
	t.Log("learn/block: DHCPv4 renewal tuple, DHCPv6 Renew, UDP/TCP DNS, NTP, IPv6 neighbor rediscovery pass; unknown v4/v6 TCP/UDP dropped")
}
