package agent

import (
	"netmonitor/internal/collect"
	"testing"
)

func TestSSHCursorAndOutboxCommitTogether(t *testing.T) {
	a, _, _, _ := agentFixture(t)
	hits := []collect.SSHFail{{IP: "198.18.45.1"}, {IP: "198.18.45.2"}}
	if _, err := a.st.DB.Exec("CREATE TRIGGER fail_cursor BEFORE INSERT ON meta WHEN new.k='ssh_cursor' BEGIN SELECT RAISE(ABORT,'full'); END"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveSSH(hits, "cursor-1"); err == nil {
		t.Fatal("SQL failure hidden")
	}
	var n int
	if err := a.st.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n); err != nil || n != 0 {
		t.Fatal("partial SSH batch", n, err)
	}
	if _, err := a.st.DB.Exec("DROP TRIGGER fail_cursor"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveSSH(hits, "cursor-1"); err != nil {
		t.Fatal(err)
	}
	if err := a.st.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n); err != nil || n != 2 {
		t.Fatal("retry", n, err)
	}
	if cur, err := meta(a.st.DB, "ssh_cursor"); err != nil || cur != "cursor-1" {
		t.Fatal("cursor", cur, err)
	}
}
