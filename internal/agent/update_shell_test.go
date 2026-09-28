package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpdateScriptPublishesOnlyAfterHealthDecision(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil && runtime.GOOS == "windows" {
		shell = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		_, err = os.Stat(shell)
	}
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	// Every service/binary mutation is intercepted; only the verdict in TempDir is written.
	mock := `
binary=old
slept=0
cp() { :; }
rm() { :; }
mv() {
 case "$2" in
  /usr/local/bin/nmagent.next) binary=new ;;
  /usr/local/bin/nmagent.prev) binary=old ;;
  "$OUTCOME.tmp") command mv "$@" ;;
  *) return 1 ;;
 esac
}
systemctl() {
 case "$*" in
  "show nmagent.service -p NRestarts --value")
   if [ "$slept" = 1 ] && [ "$CASE" != good ]; then echo 1; else echo 0; fi ;;
  "show nmagent.service -p MainPID --value") echo 123 ;;
  "start nmagent.service")
   if [ "$CASE" = rollback-fails ] && [ "$binary" = old ]; then return 1; fi ;;
  *) : ;;
 esac
}
sleep() {
 [ "$1" = 20 ] || exit 95
 if [ -e "$OUTCOME" ]; then echo premature-result >&2; exit 96; fi
 slept=1
}
`
	for _, scenario := range []string{"good", "crash", "rollback-fails"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			outcome := filepath.Join(dir, "outcome")
			cmd := exec.Command(shell, "-c", mock+updateScript, "test-updater", filepath.ToSlash(outcome))
			cmd.Env = append(os.Environ(), "OUTCOME="+filepath.ToSlash(outcome), "CASE="+scenario)
			out, runErr := cmd.CombinedOutput()
			if strings.Contains(string(out), "premature-result") {
				t.Fatal(string(out))
			}
			raw, err := os.ReadFile(outcome)
			if err != nil {
				t.Fatal(err, runErr, string(out))
			}
			want := map[string]string{"good": "verified", "crash": "rolledback", "rollback-fails": "failed"}[scenario]
			if strings.TrimSpace(string(raw)) != want || (runErr == nil) != (scenario == "good") {
				t.Fatal(string(raw), runErr, string(out))
			}
		})
	}
}
