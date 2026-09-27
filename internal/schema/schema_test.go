package schema_test

import (
	"path/filepath"
	"testing"

	"netmonitor/internal/store"
)

func TestMonitorSchema(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := []string{
		"hosts", "agents", "ingest_events", "flows", "flow_samples",
		"traffic_1m", "never_block", "blocks", "settings", "enroll_tokens",
	}
	want = append(want, "block_pause")
	for _, name := range want {
		var n int
		if err := st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=?`, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("нет %s", name)
		}
	}
	for _, v := range []string{"v_flows", "v_contacts_in", "v_contacts_out", "v_no_reply", "v_own", "v_gaps"} {
		var n int
		if err := st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=? AND type='view'`, v).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("нет вьюхи %s", v)
		}
	}
}

func TestAgentSchema(t *testing.T) {
	st, err := store.OpenAgent(filepath.Join(t.TempDir(), "x"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='outbox'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("нет outbox")
	}
}
