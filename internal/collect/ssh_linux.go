//go:build linux

package collect

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func ReadSSHFailures(cursor string) ([]SSHFail, string, error) {
	args := []string{"-q", "--no-pager", "-o", "json", "-u", "ssh", "-u", "sshd", "--show-cursor", "-n", "500"}
	if cursor != "" {
		args = append([]string{"--after-cursor=" + cursor}, args...)
	} else {
		args = append([]string{"--since=-12min"}, args...)
	}
	cmd := exec.Command("journalctl", args...)
	out, _ := cmd.CombinedOutput()
	next := cursor
	var hits []SSHFail
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "-- cursor:") {
			i := strings.Index(line, "cursor:")
			next = strings.TrimSpace(line[i+len("cursor:"):])
			continue
		}
		var rec struct {
			Cursor   string `json:"__CURSOR"`
			Realtime string `json:"__REALTIME_TIMESTAMP"`
			Message  string `json:"MESSAGE"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Cursor != "" {
			next = rec.Cursor
		}
		ip, user, ok := parseSSHMessage(rec.Message)
		if !ok {
			continue
		}
		at := time.Now().UTC().UnixMilli()
		if rec.Realtime != "" {
			if us, err := strconv.ParseInt(rec.Realtime, 10, 64); err == nil {
				at = us / 1000
			}
		}
		hits = append(hits, SSHFail{IP: ip, User: user, Note: rec.Message, AtMS: at})
	}
	if next == "" {
		next = cursor
	}
	return hits, next, nil
}
