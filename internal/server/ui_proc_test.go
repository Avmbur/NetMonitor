package server

import "testing"

func TestDisplayProc(t *testing.T) {
	if got := displayProc("sshd", ""); got != "sshd" {
		t.Fatalf("comm %q", got)
	}
	if got := displayProc("", "/usr/bin/fwupdmgr"); got != "fwupdmgr" {
		t.Fatalf("path %q", got)
	}
	if got := displayProc("", "cgroup=system.slice/nginx.service"); got != "" {
		t.Fatalf("cgroup %q", got)
	}
	if got := displayProc("https", "/usr/lib/apt/methods/http uid=42 cgroup=system.slice/esm-cache.service"); got != "apt" {
		t.Fatalf("apt %q", got)
	}
	if got := displayProc("http", "/usr/lib/apt/methods/http uid=42 cgroup=system.slice/apt-daily.service"); got != "apt" {
		t.Fatalf("apt http %q", got)
	}
	if got := displayProc("", "/usr/sbin/sshd uid=0 cgroup=system.slice/ssh.service"); got != "sshd" {
		t.Fatalf("path wins %q", got)
	}
	if got := displayProc("check-new-relea", "/usr/bin/python3.14 uid=0 cgroup=user.slice/user-1001.slice/session-304.scope"); got != "python3.14" {
		t.Fatalf("python %q", got)
	}
	if got := displayProc("ядро", ""); got != "" {
		t.Fatalf("fake %q", got)
	}
	if got := displayProc("", ""); got != "" {
		t.Fatalf("empty %q", got)
	}
}

func TestNtpUbuntuName(t *testing.T) {
	if got := ntpUbuntuName("185.125.190.121", "udp", 123); got != "ntp.ubuntu.com" {
		t.Fatalf("pool %q", got)
	}
	if got := ntpUbuntuName("91.189.91.111", "udp", 123); got != "ntp.ubuntu.com" {
		t.Fatalf("pool2 %q", got)
	}
	if got := ntpUbuntuName("185.125.190.36", "tcp", 443); got != "" {
		t.Fatalf("https %q", got)
	}
	if got := ntpUbuntuName("1.1.1.1", "udp", 123); got != "" {
		t.Fatalf("other %q", got)
	}
}
