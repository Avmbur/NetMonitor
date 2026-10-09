package collect

import "regexp"

type SSHFail struct {
	IP   string
	User string
	Note string
	AtMS int64
}

// OpenSSH emits one terminal authentication result in addition to diagnostic
// messages about invalid users, PAM and disconnects. Counting the diagnostics
// too turns one wrong password into multiple attempts. The "none" method is
// only an authentication-method probe and is not a credential attempt.
var sshFailure = regexp.MustCompile(`(?i)^Failed (?:password|publickey|keyboard-interactive(?:/pam)?|hostbased|gssapi-with-mic) for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port [0-9]+\b`)

func parseSSHMessage(msg string) (ip, user string, ok bool) {
	m := sshFailure.FindStringSubmatch(msg)
	if m == nil {
		return "", "", false
	}
	return m[2], m[1], true
}
