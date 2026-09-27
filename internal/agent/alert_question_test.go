package agent

import (
	"testing"

	"netmonitor/internal/collect"

	pol "netmonitor/internal/policy"
	"netmonitor/internal/store"
)

func TestAlertGroupKeepsQuestion(t *testing.T) {
	st, err := store.OpenAgent(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Agent{st: st, managed: true, mode: "park"}
	a.groups = []pol.Rule{{ID: "g1", Name: "Телеметрия", Enabled: true, Action: "alert", Version: 1,
		Match: pol.Match{Networks: []string{"203.0.113.50/32"}}}}
	a.enqueueLearnProcess("out", "tcp", "203.0.113.50", 0, 9, collect.Process{Comm: "curl", Path: "/usr/bin/curl"})
	var n int
	st.DB.QueryRow("SELECT COUNT(*) FROM local_questions").Scan(&n)
	if n != 1 {
		t.Fatal("alert group did not raise a question", n)
	}
}
