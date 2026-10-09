package agent

import (
	"database/sql"
	"netmonitor/internal/collect"
	"testing"
)

func TestSSHCursorAndEventsStayInMemory(t *testing.T) {
	a, _, _, _ := agentFixture(t)
	a.prepareSpool()
	hits := []collect.SSHFail{{IP: "198.18.45.1", AtMS: a.telemetrySince}, {IP: "198.18.45.2", AtMS: a.telemetrySince}}
	if _, err := a.st.DB.Exec("CREATE TRIGGER fail_cursor BEFORE INSERT ON meta WHEN new.k='ssh_cursor' BEGIN SELECT RAISE(ABORT,'full'); END"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveSSH(hits, "cursor-1"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, it := range a.plan.copy() {
		if it.kind == "ssh" {
			n++
		}
	}
	if n != 2 {
		t.Fatal("SSH events", n)
	}
	if err := a.st.DB.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&n); err != nil || n != 0 {
		t.Fatal("SSH written to disk", n, err)
	}
	if cur, err := meta(a.st.DB, "ssh_cursor"); err != sql.ErrNoRows || cur != "" {
		t.Fatal("disk cursor", cur, err)
	}
}
