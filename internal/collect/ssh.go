package collect

import "regexp"

type SSHFail struct {
	IP   string
	User string
	Note string
	AtMS int64
}

var sshFailKind = regexp.MustCompile(`(?i)failed password|invalid user|failed publickey|authentication failure|connection closed by authenticating user|disconnected from authenticating user`)
var sshFrom = regexp.MustCompile(`(?i)(?:from |rhost=)([0-9a-fA-F:.]+)`)
var sshAuthIP = regexp.MustCompile(`(?i)authenticating user \S+ ([0-9a-fA-F:.]+) port`)
var sshUser = regexp.MustCompile(`(?i)(?:for(?: invalid user)? |user )([^\s]+)`)

func parseSSHMessage(msg string) (ip, user string, ok bool) {
	if !sshFailKind.MatchString(msg) {
		return "", "", false
	}
	m := sshFrom.FindStringSubmatch(msg)
	if m == nil {
		m = sshAuthIP.FindStringSubmatch(msg)
	}
	if m == nil {
		return "", "", false
	}
	if um := sshUser.FindStringSubmatch(msg); len(um) > 1 {
		user = um[1]
	}
	return m[1], user, true
}
