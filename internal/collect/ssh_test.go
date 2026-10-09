package collect

import "testing"

func TestParseSSHMessageUbuntuJournal(t *testing.T) {
	for _, tc := range []struct{ msg, ip, user string }{
		{"Failed password for root from 203.0.113.9 port 22 ssh2", "203.0.113.9", "root"},
		{"Failed password for invalid user guest from 2001:db8::1 port 22 ssh2", "2001:db8::1", "guest"},
		{"Failed publickey for guest from 203.0.113.10 port 45123 ssh2: RSA SHA256:example", "203.0.113.10", "guest"},
		{"Failed keyboard-interactive/pam for root from 203.0.113.11 port 45124 ssh2", "203.0.113.11", "root"},
	} {
		ip, user, ok := parseSSHMessage(tc.msg)
		if !ok || ip != tc.ip || user != tc.user {
			t.Fatalf("%q: %q %q %v", tc.msg, ip, user, ok)
		}
	}
	for _, msg := range []string{
		"Connection closed by authenticating user nobody 192.168.10.184 port 49522 [preauth]",
		"Disconnected from authenticating user nobody 192.168.10.184 port 49522 [preauth]",
		"Invalid user guest from 2001:db8::1 port 22",
		"pam_unix(sshd:auth): authentication failure; rhost=192.168.10.184",
		"Failed none for invalid user guest from 192.168.10.184 port 22 ssh2",
		"Accepted password for test from 192.168.10.185 port 22 ssh2",
		"Invalid user Failed password for root from 198.18.13.2 port 22",
	} {
		if _, _, ok := parseSSHMessage(msg); ok {
			t.Fatalf("diagnostic counted as an authentication attempt: %q", msg)
		}
	}
}

func TestSSHOneAttemptIsNotThreeJournalMessages(t *testing.T) {
	messages := []string{
		"Invalid user guest from 198.18.13.2 port 51890",
		"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.18.13.2",
		"Failed password for invalid user guest from 198.18.13.2 port 51890 ssh2",
		"Connection closed by invalid user guest 198.18.13.2 port 51890 [preauth]",
	}
	n := 0
	for _, msg := range messages {
		if _, _, ok := parseSSHMessage(msg); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one password attempt counted %d times", n)
	}
}
