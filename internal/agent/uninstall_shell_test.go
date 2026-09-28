package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemovalShellFailuresNeverConfirm(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil && runtime.GOOS == "windows" {
		shell = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		_, err = os.Stat(shell)
	}
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	// Shell functions intercept every mutating command; no real services/files are touched.
	mock := `
systemctl() {
 printf 'systemctl %s\n' "$*" >&2
 case "$*" in
  *LoadState*) echo loaded ;;
  *ActiveState*) if [ "$FAIL" = alive ]; then echo active; else echo inactive; fi ;;
  "disable --now nmagent.service") [ "$FAIL" != stop ] ;;
  "daemon-reload") [ "$FAIL" != reload ] ;;
 esac
}
TABLE_PRESENT=1
nft() {
 printf 'nft %s\n' "$*" >&2
 case "$*" in
  "list tables")
   [ "$FAIL" != list ] || return 1
   if [ "$TABLE_PRESENT" = 1 ]; then echo 'table inet netmon'; fi ;;
  "delete table inet netmon")
   [ "$FAIL" != nft ] || return 1
   if [ "$FAIL" != remains ]; then TABLE_PRESENT=0; fi ;;
  *) return 1 ;;
 esac
}
rm() {
 printf 'rm %s\n' "$*" >&2
 [ "$FAIL" != files ]
}
`
	for _, fail := range []string{"", "stop", "alive", "list", "nft", "remains", "files", "reload"} {
		t.Run(fail, func(t *testing.T) {
			var phases []string
			var output []byte
			marker := false
			err := runUninstallJob(false, func() error {
				cmd := exec.Command(shell, "-c", mock+uninstallScript)
				cmd.Env = append(os.Environ(), "FAIL="+fail)
				var err error
				output, err = cmd.CombinedOutput()
				return err
			}, func() error { marker = true; return nil }, func(phase, message string) error { phases = append(phases, phase); return nil })
			if fail == "" {
				if err != nil || !marker || strings.Join(phases, ",") != "prepare,complete" {
					t.Fatalf("%v %v %s", err, phases, output)
				}
				text := string(output)
				if strings.Index(text, "disable --now") > strings.Index(text, "delete table") {
					t.Fatal(text)
				}
			} else {
				if err == nil || marker || strings.Join(phases, ",") != "prepare,failed" {
					t.Fatalf("%v %v %s", err, phases, output)
				}
				if (fail == "stop" || fail == "alive") && strings.Contains(string(output), "nft ") {
					t.Fatal("firewall touched before confirmed stop")
				}
				if (fail == "list" || fail == "nft" || fail == "remains") && strings.Contains(string(output), "rm ") {
					t.Fatal("files removed before firewall cleanup")
				}
			}
		})
	}
}
