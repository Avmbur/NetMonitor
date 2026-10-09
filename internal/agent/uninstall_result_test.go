package agent

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"netmonitor/internal/protocol"
)

func TestRemovalJobFailureAndLostCompletion(t *testing.T) {
	boom := errors.New("failure")
	for _, failed := range []string{"prepare", "cleanup", "mark", "complete", ""} {
		t.Run(failed, func(t *testing.T) {
			var calls []string
			step := func(name string) error {
				calls = append(calls, name)
				if name == failed {
					return boom
				}
				return nil
			}
			err := runUninstallJob(false, func() error { return step("cleanup") }, func() error { return step("mark") }, func(phase, message string) error { return step(phase) })
			expected := map[string][]string{
				"prepare":  {"prepare"},
				"cleanup":  {"prepare", "cleanup", "failed"},
				"mark":     {"prepare", "cleanup", "mark"},
				"complete": {"prepare", "cleanup", "mark", "complete"},
				"":         {"prepare", "cleanup", "mark", "complete"},
			}[failed]
			if !reflect.DeepEqual(calls, expected) || (err != nil) != (failed != "") {
				t.Fatal(calls, err)
			}
		})
	}
	// A durable success marker survives a crash or lost response.
	var calls []string
	err := runUninstallJob(true, func() error { t.Fatal("cleanup repeated"); return nil }, func() error { t.Fatal("marker rewritten"); return nil }, func(phase, message string) error { calls = append(calls, phase); return nil })
	if err != nil || !reflect.DeepEqual(calls, []string{"complete"}) {
		t.Fatal(calls, err)
	}
}

func TestRemovalRequiresExplicitHTTPAcknowledgement(t *testing.T) {
	for _, body := range []string{`{"ok":true}`, `{"ok":false}`, `{}`, `broken`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		err := sendUninstallResult(srv.Client(), srv.URL, protocol.UninstallResult{CommandID: "x", Phase: "complete"})
		srv.Close()
		if (err == nil) != (body == `{"ok":true}`) {
			t.Fatal(body, err)
		}
	}
}

func TestPendingUninstallStillStarts(t *testing.T) {
	a, f, reports, _ := agentFixture(t)
	started := 0
	a.startRemoval = func(id string) error {
		if id != "remove" {
			t.Fatal(id)
		}
		started++
		return nil
	}
	pr := policy(1)
	pr.Authorized = false
	pr.Commands = []protocol.Command{{ID: "remove", Kind: "uninstall"}}
	if err := a.applyPoll(pr); err != nil {
		t.Fatal(err)
	}
	if started != 1 || f.calls != 0 {
		t.Fatal(started, f.calls)
	}
	for _, r := range *reports {
		if r.Uninstalled != "" || len(r.Ack) > 0 {
			t.Fatal("pending removal claimed success", r)
		}
	}
}

func TestRemovalSchedulingNeverClaimsCompletion(t *testing.T) {
	for _, failFW := range []bool{false, true} {
		a, f, reports, _ := agentFixture(t)
		if failFW {
			f.err = errors.New("broken firewall")
		}
		started := 0
		a.startRemoval = func(id string) error {
			if id != "remove" {
				t.Fatal(id)
			}
			started++
			return nil
		}
		pr := policy(2)
		pr.Commands = []protocol.Command{{ID: "remove", Kind: "uninstall"}}
		_ = a.applyPoll(pr)
		if started != 1 {
			t.Fatal("firewall error blocked removal")
		}
		for _, r := range *reports {
			if r.Uninstalled != "" || len(r.Ack) > 0 {
				t.Fatal("premature completion", r)
			}
		}
	}
}

func TestRemovalStartFailureIsRetryable(t *testing.T) {
	a, _, reports, _ := agentFixture(t)
	starts := 0
	a.startRemoval = func(string) error { starts++; return errors.New("cannot start service") }
	pr := policy(2)
	pr.Commands = []protocol.Command{{ID: "remove", Kind: "uninstall"}}
	for range 2 {
		if err := a.applyPoll(pr); err == nil {
			t.Fatal("launch failure hidden")
		}
	}
	if starts != 2 {
		t.Fatal("redelivery not retried")
	}
	for _, r := range *reports {
		if r.Uninstalled != "" || len(r.Ack) > 0 {
			t.Fatal("failed launch acknowledged")
		}
	}
}
