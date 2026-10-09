package agent

import (
	"strings"
	"testing"
)

func TestUninstallScriptLeavesMonitor(t *testing.T) {
	if strings.Contains(uninstallScript, "nmserver") || strings.Contains(uninstallScript, "/var/lib/nmserver") {
		t.Fatal("script touches the monitor")
	}
	for _, part := range []string{"nft delete table inet", "for table in netmon netmon_collect", "nmagent.service", "nmagent-restore.service", "/usr/local/bin/nmagent", "/var/lib/nmagent"} {
		if !strings.Contains(uninstallScript, part) {
			t.Fatal("missing", part)
		}
	}
	if strings.Index(uninstallScript, "disable --now") > strings.Index(uninstallScript, "nft delete table") {
		t.Fatal("table is removed before the agent stops")
	}
}
