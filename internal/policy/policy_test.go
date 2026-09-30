package policy

import (
	"strings"
	"testing"
)

func uid(n int) *int { return &n }

func TestDedicatedCgroupAndIdentity(t *testing.T) {
	if !DedicatedCgroup("/system.slice/nginx.service") || !DedicatedCgroup("nginx.service") || !DedicatedCgroup("system.slice/docker-abc.scope") {
		t.Fatal("service/container cgroup rejected")
	}
	for _, p := range []string{"/", "user.slice/user-1000.slice/session-3.scope", "init.scope", "user.slice/user-1000.slice"} {
		if DedicatedCgroup(p) {
			t.Fatal("shared cgroup accepted", p)
		}
	}
	b, err := ParseIdentity("cgroup=nginx.service", "h1", "nginx")
	term, e := CgroupMatch(b.Cgroup)
	if err != nil || e != nil || b.Cgroup != "system.slice/nginx.service" || !strings.Contains(term, "socket cgroupv2") {
		t.Fatal(b, err, term, e)
	}
	if _, err = ParseIdentity("nginx", "", ""); err == nil {
		t.Fatal("name-only parsed")
	}
	pathOnly, err := ParseIdentity("/usr/bin/python3", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = pathOnly.Enforceable(); err == nil || !strings.Contains(err.Error(), "без uid") {
		t.Fatal(err)
	}
	curl, err := ParseIdentity("/usr/bin/curl uid=1000", "h", "curl")
	if err != nil {
		t.Fatal(err)
	}
	if err = curl.Enforceable(); err == nil || !strings.Contains(err.Error(), "все программы") {
		t.Fatal(err)
	}
}

func TestProcessBindingDoesNotWidenToAddressOrUID(t *testing.T) {
	nginx := Binding{Host: "h1", Name: "nginx", Cgroup: "system.slice/nginx.service", Path: "/usr/sbin/nginx", UID: uid(33)}
	r := Rule{ID: "p", Enabled: true, Action: "allow", Match: Match{Bindings: []Binding{nginx}, Direction: "out", Protocol: "tcp", RemotePort: 80, Networks: []string{"198.18.0.2/32"}}}
	if err := Executable(r); err != nil {
		t.Fatal(err)
	}
	now := int64(1000)
	hit := func(c Contact) bool {
		_, ok := Evaluate([]Rule{r}, "h1", c, now)
		return ok
	}
	base := Contact{Direction: "out", Protocol: "tcp", RemoteIP: "198.18.0.2", RemotePort: 80, Process: "/usr/sbin/nginx", Cgroup: "/system.slice/nginx.service", UID: uid(33)}
	if !hit(base) {
		t.Fatal("own process missed")
	}
	foreign := base
	foreign.Process, foreign.Cgroup = "/usr/bin/python3", "/user.slice/user-33.slice/session-1.scope"
	if hit(foreign) {
		t.Fatal("same uid different process allowed")
	}
	otherHost := base
	if _, ok := Evaluate([]Rule{r}, "h2", otherHost, now); ok {
		t.Fatal("binding expanded to another host")
	}
	sameName := base
	sameName.Cgroup = "/system.slice/other.service"
	if hit(sameName) {
		t.Fatal("same name different cgroup allowed")
	}
	if err := Executable(Rule{Action: "allow", Match: Match{Process: "/usr/bin/python3"}}); err == nil {
		t.Fatal("path-only saved")
	}
	if err := Executable(Rule{Action: "allow", Match: Match{UID: uid(1000), Networks: []string{"1.1.1.1/32"}}}); err == nil {
		t.Fatal("uid-only saved")
	}
}

func TestOnceSpentOnceAndKeepsParallelBlocked(t *testing.T) {
	r := Rule{ID: "o", Enabled: true, Action: "allow", Once: true, Match: Match{Direction: "out", Protocol: "tcp", RemotePort: 443, Networks: []string{"198.18.0.2/32"}}}
	if err := Executable(r); err != nil {
		t.Fatal(err)
	}
	c := Contact{Direction: "out", Protocol: "tcp", RemoteIP: "198.18.0.2", RemotePort: 443}
	if _, ok := Evaluate([]Rule{r}, "h", c, 1); !ok {
		t.Fatal("first flow missed")
	}
	r.OnceUsed = true
	if _, ok := Evaluate([]Rule{r}, "h", c, 1); ok {
		t.Fatal("restart rearmed once")
	}
	r.OnceUsed = false
	r.OnceUsedHosts = []string{"h"}
	if _, ok := Evaluate([]Rule{r}, "h", c, 1); ok {
		t.Fatal("host spend ignored")
	}
	if _, ok := Evaluate([]Rule{r}, "h2", c, 1); !ok {
		t.Fatal("other host spent")
	}
	if err := Executable(Rule{Action: "deny", Once: true, Match: Match{Networks: []string{"1.1.1.1/32"}}}); err == nil {
		t.Fatal("once deny saved")
	}
	if err := Executable(Rule{Action: "allow", Once: true}); err == nil {
		t.Fatal("empty once saved")
	}
}

func TestMergeNetworksKeepsAnyWhenNothingAdded(t *testing.T) {
	if MergeNetworks(nil, nil) != nil {
		t.Fatal("nil widened")
	}
	got := MergeNetworks(nil, []string{"203.0.113.10/32", "203.0.113.10/32", "203.0.113.11/32"})
	if len(got) != 2 || got[0] != "203.0.113.10/32" || got[1] != "203.0.113.11/32" {
		t.Fatal(got)
	}
	again := MergeNetworks([]string{"203.0.113.10/32"}, []string{"203.0.113.11/32"})
	if len(again) != 2 {
		t.Fatal(again)
	}
}

func TestOnDemandNeverMeansAnyAddress(t *testing.T) {
	m := Match{Direction: "out", Protocol: "tcp", RemotePort: 443, OnDemand: []string{"github.com"}}
	c := Contact{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443}
	if m.Matches(c) {
		t.Fatal("on-demand rule matched an address nobody admitted")
	}
	m.Networks = []string{"203.0.113.9/32"}
	if !m.Matches(c) {
		t.Fatal("explicit address lost")
	}
}
