package collect

import "testing"

func TestParseSSHMessageUbuntuJournal(t *testing.T) {
	ip, user, ok := parseSSHMessage("Connection closed by authenticating user nobody 192.168.10.184 port 49522 [preauth]")
	if !ok || ip != "192.168.10.184" || user != "nobody" {
		t.Fatal(ip, user, ok)
	}
	ip, user, ok = parseSSHMessage("Failed password for root from 203.0.113.9 port 22 ssh2")
	if !ok || ip != "203.0.113.9" || user != "root" {
		t.Fatal(ip, user, ok)
	}
	ip, user, ok = parseSSHMessage("Invalid user guest from 2001:db8::1 port 22")
	if !ok || ip != "2001:db8::1" || user != "guest" {
		t.Fatal(ip, user, ok)
	}
	if _, _, ok = parseSSHMessage("Accepted password for test from 192.168.10.185 port 22 ssh2"); ok {
		t.Fatal("accepted counted")
	}
}
