//go:build linux

package fw

import (
	"fmt"
	"net"
	"net/netip"
	"netmonitor/internal/policy"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExactPolicyKernel(t *testing.T) {
	if os.Getenv("NM_FW_NETNS_TEST") != "1" {
		t.Skip("isolated root namespace")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		b, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v %s", name, args, e, b)
		}
		return string(b)
	}
	peer := exec.Command("unshare", "-n", "sleep", "90")
	if e := peer.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	pid := strconv.Itoa(peer.Process.Pid)
	self, _ := os.Readlink("/proc/self/ns/net")
	for i := 0; i < 100; i++ {
		ns, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if ns != "" && ns != self {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "plocal", "type", "veth", "peer", "name", "premote")
	run("ip", "link", "set", "premote", "netns", pid)
	run("ip", "addr", "add", "198.18.1.1/24", "dev", "plocal")
	run("ip", "-6", "addr", "add", "fd00:3::1/64", "dev", "plocal", "nodad")
	run("ip", "link", "set", "plocal", "up")
	ns := func(args ...string) string { return run("nsenter", append([]string{"-t", pid, "-n"}, args...)...) }
	ns("ip", "link", "set", "lo", "up")
	ns("ip", "addr", "add", "198.18.1.2/24", "dev", "premote")
	ns("ip", "-6", "addr", "add", "fd00:3::2/64", "dev", "premote", "nodad")
	ns("ip", "link", "set", "premote", "up")
	code := `import socket,threading,time
def tcp(port):
 s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('::',port));s.listen()
 def echo(c):
  try:
   while True:
    b=c.recv(100)
    if not b:break
    c.sendall(b)
  except OSError:pass
  c.close()
 while True:
  c,a=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
def udp(port):
 s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('::',port))
 while True:
  b,a=s.recvfrom(100);s.sendto(b,a)
for p in [18080,18443,53]:threading.Thread(target=tcp,args=(p,),daemon=True).start()
for p in [18080,53,123]:threading.Thread(target=udp,args=(p,),daemon=True).start()
time.sleep(80)`
	srv := exec.Command("nsenter", "-t", pid, "-n", "python3", "-c", code)
	if e := srv.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	time.Sleep(200 * time.Millisecond)
	echo := func(proto, ip string, port int, want bool) {
		t.Helper()
		c, e := net.DialTimeout(proto, net.JoinHostPort(ip, strconv.Itoa(port)), 300*time.Millisecond)
		ok := false
		if e == nil {
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			_, e = c.Write([]byte("x"))
			if e == nil {
				buf := make([]byte, 1)
				n, err := c.Read(buf)
				ok = err == nil && n == 1 && buf[0] == 'x'
			}
			c.Close()
		}
		if ok != want {
			t.Fatalf("%s %s:%d got %v want %v (%v)", proto, ip, port, ok, want, e)
		}
	}
	c := NewController()
	r := policy.Rule{ID: "test", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 18080, Networks: []string{"198.18.1.2/32", "fd00:3::2/128"}}}
	p := Policy{Managed: true, Mode: "learn", Rules: []policy.Rule{r}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"198.18.1.2", "fd00:3::2"} {
		echo("tcp", ip, 18080, true)
		echo("tcp", ip, 18443, false)
		echo("udp", ip, 18080, false)
	}
	if !c.Alive() {
		t.Fatal("new policy fails integrity")
	}
	// Input uses the local service port; "any" matches either side without changing
	// the initiator direction. Exercise packets, not just generated strings.
	localServer := exec.Command("python3", "-c", code)
	if e := localServer.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { localServer.Process.Kill(); localServer.Wait() }()
	time.Sleep(100 * time.Millisecond)
	incoming := func(proto, ip string, port int, want bool) {
		t.Helper()
		script := fmt.Sprintf("import socket\ns=socket.socket(socket.AF_INET6 if ':' in %q else socket.AF_INET,socket.SOCK_DGRAM if %q=='udp' else socket.SOCK_STREAM);s.settimeout(.3)\ntry:\n s.connect((%q,%d));s.send(b'x');print('ok' if s.recv(1)==b'x' else 'bad')\nexcept OSError:print('blocked')", ip, proto, ip, port)
		result := strings.TrimSpace(ns("python3", "-c", script))
		if (result == "ok") != want {
			t.Fatalf("input %s %s:%d result=%s", proto, ip, port, result)
		}
	}
	p.Rules = []policy.Rule{{ID: "incoming", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 18080}}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"198.18.1.1", "fd00:3::1"} {
		incoming("tcp", ip, 18080, true)
		incoming("tcp", ip, 18443, false)
		incoming("udp", ip, 18080, false)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	p.Rules[0].Match.LocalPort = 0
	p.Rules[0].Match.AnyPort = 18080
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	incoming("tcp", "198.18.1.1", 18080, true)
	echo("tcp", "198.18.1.2", 18080, false)
	p.Rules = []policy.Rule{r}
	// Existing TCP is stopped by a precise outgoing ban; unrelated port remains open.
	p.Mode = "allow"
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	for _, pair := range [][2]string{{"198.18.1.1", "198.18.1.2"}, {"fd00:3::1", "fd00:3::2"}} {
		local, remote := pair[0], pair[1]
		p.Blocks = nil
		if e := c.Apply(p); e != nil {
			t.Fatal(e)
		}
		live, e := net.Dial("tcp", net.JoinHostPort(remote, "18080"))
		if e != nil {
			t.Fatal(e)
		}
		p.Blocks = []Desired{{BlockID: "exact", IP: netip.MustParseAddr(remote), Port: 18080, Protocol: "tcp", Direction: "out"}}
		if e := c.Apply(p); e != nil {
			live.Close()
			t.Fatal(e)
		}
		echo("tcp", remote, 18080, false)
		echo("tcp", remote, 18443, true)
		echo("udp", remote, 18080, true)
		incoming("tcp", local, 18080, true)
		live.SetDeadline(time.Now().Add(300 * time.Millisecond))
		live.Write([]byte("x"))
		buf := make([]byte, 1)
		_, e = live.Read(buf)
		live.Close()
		if e == nil {
			t.Fatal("existing session survived exact ban")
		}
		if !c.Alive() {
			t.Fatal("precise ban fails integrity")
		}
	}
	// Addressless local port applies to both families and expires in the kernel.
	p.Blocks = []Desired{{BlockID: "local", LocalPort: 18080, Protocol: "tcp", Direction: "in", ExpiresAtMS: (time.Now().Unix() + 5) * 1000}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	for _, pair := range [][2]string{{"198.18.1.1", "198.18.1.2"}, {"fd00:3::1", "fd00:3::2"}} {
		incoming("tcp", pair[0], 18080, false)
		incoming("tcp", pair[0], 18443, true)
		incoming("udp", pair[0], 18080, true)
		echo("tcp", pair[1], 18080, true)
	}
	time.Sleep(time.Until(time.UnixMilli(p.Blocks[0].ExpiresAtMS)) + 100*time.Millisecond)
	incoming("tcp", "198.18.1.1", 18080, true)
	incoming("tcp", "fd00:3::1", 18080, true)
	p.Blocks = nil
	p.Mode = "learn"
	deny := policy.Rule{ID: "group-block", Enabled: true, Action: "deny", Match: policy.Match{Networks: []string{"198.18.1.0/24"}}}
	allow := deny
	allow.ID = "group-allow"
	allow.Action = "observe"
	allow.Order = -1
	p.Groups = []policy.Rule{deny}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	p.Groups = []policy.Rule{deny, allow}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, true)
	allow.Order = 0
	p.Groups = []policy.Rule{allow, deny}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	p.Never = []netip.Prefix{netip.MustParsePrefix("198.18.1.2/32")}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, true)
	p.Never = nil
	// Quarantine overrides both an explicit allow and an allow group, then removal
	// restores the saved rules. Never-block still has absolute priority.
	p.Groups = []policy.Rule{allow}
	p.Mode = "quarantine"
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	echo("tcp", "fd00:3::2", 18080, false)
	for _, ip := range []string{"198.18.1.2", "fd00:3::2"} {
		echo("tcp", ip, 53, true)
		echo("udp", ip, 53, true)
		echo("udp", ip, 123, true)
	}

	p.Never = []netip.Prefix{netip.MustParsePrefix("198.18.1.2/32")}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, true)
	p.Never = nil
	p.Mode = "learn"
	p.Groups = nil
	p.Rules[0].FromMS = (time.Now().Unix() + 2) * 1000
	p.Rules[0].UntilMS = p.Rules[0].FromMS + 2000
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	time.Sleep(time.Until(time.UnixMilli(p.Rules[0].FromMS)) + 100*time.Millisecond)
	echo("tcp", "198.18.1.2", 18080, true)
	time.Sleep(time.Until(time.UnixMilli(p.Rules[0].UntilMS)) + 100*time.Millisecond)
	echo("tcp", "198.18.1.2", 18080, false)
	p.Rules = []policy.Rule{{ID: "once", Enabled: true, Action: "allow", Once: true, Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 18080, Networks: []string{"198.18.1.2/32", "fd00:3::2/128"}}}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, true)
	echo("tcp", "198.18.1.2", 18080, false)
	echo("tcp", "fd00:3::2", 18080, false)
	spent := p.Rules[0]
	spent.OnceUsed = true
	p.Rules[0] = spent
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	cgDir := "/sys/fs/cgroup/system.slice/nm-exact-proc.service"
	if e := os.MkdirAll(cgDir, 0755); e != nil {
		t.Log("cgroup skip", e)
		return
	}
	defer os.Remove(cgDir)
	p.Rules = []policy.Rule{{ID: "cg", Enabled: true, Action: "allow", Match: policy.Match{Direction: "out", Protocol: "tcp", RemotePort: 18080, Networks: []string{"198.18.1.2/32"}, Bindings: []policy.Binding{{Cgroup: "system.slice/nm-exact-proc.service"}}}}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	child := exec.Command("python3", "-c", "import os,socket,sys\nopen('/sys/fs/cgroup/system.slice/nm-exact-proc.service/cgroup.procs','w').write(str(os.getpid()))\ns=socket.create_connection(('198.18.1.2',18080),1);s.send(b'x');sys.exit(0 if s.recv(1)==b'x' else 1)")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("cgroup child: %v %s", e, out)
	}
	echo("tcp", "198.18.1.2", 18080, false)
	listen := exec.Command("python3", "-c", "import os,socket,threading\nopen('/sys/fs/cgroup/system.slice/nm-exact-proc.service/cgroup.procs','w').write(str(os.getpid()))\ns=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('::',18081));s.listen()\nwhile True:\n c,a=s.accept();threading.Thread(target=lambda x: (x.sendall(x.recv(8) or b''),x.close()),args=(c,),daemon=True).start()")
	if e := listen.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { listen.Process.Kill(); listen.Wait() }()
	time.Sleep(150 * time.Millisecond)
	p.Rules = []policy.Rule{{ID: "cgin", Enabled: true, Action: "allow", Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 18081, Bindings: []policy.Binding{{Cgroup: "system.slice/nm-exact-proc.service"}}}}}
	if e := c.Apply(p); e != nil {
		t.Fatal(e)
	}
	incoming("tcp", "198.18.1.1", 18081, true)
	incoming("tcp", "198.18.1.1", 18080, false)
	incoming("tcp", "fd00:3::1", 18081, true)
}
