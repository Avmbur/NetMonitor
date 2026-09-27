package server

import (
	"strings"
	"testing"
	"time"

	"netmonitor/internal/policy"
)

func TestFormatPolicyDump(t *testing.T) {
	when := time.Date(2026, 9, 23, 16, 40, 0, 0, time.UTC)
	uid := 33
	txt := formatPolicyDump(when, []string{"dev-postgres", "монитор"}, []uiGroup{{
		ID: "telem", Name: "телеметрия", Policy: "block",
		Members: "52.84.12.0/24\n*.telemetry.example",
		Hosts:   []byte(`"all"`),
		Except:  []string{"h-vpn"},
	}}, []policy.Rule{{
		Name: "SSH", Enabled: true, Action: "allow",
		Match: policy.Match{Direction: "in", Protocol: "tcp", LocalPort: 22},
	}, {
		Name:    "служебные · порт монитора (руками не трогать)",
		Enabled: true, Action: "allow",
		Hosts: []string{"h-mon"},
		Match: policy.Match{Direction: "any", Protocol: "tcp", AnyPort: 8443, Networks: []string{"10.0.0.0/8"}, Process: "sshd", Bindings: []policy.Binding{{Host: "h-mon", Path: "/usr/sbin/sshd", UID: &uid}}},
	}}, map[string]string{"h-vpn": "vpn-1", "h-mon": "монитор"})
	if strings.Contains(txt, "h-vpn") || strings.Contains(txt, "h-mon") {
		t.Fatal("uuid/id leaked", txt)
	}
	for _, want := range []string{
		"выгрузка 23.09.2026 16:40",
		"серверы: dev-postgres, монитор",
		"--- телеметрия ---",
		"политика: блокировать",
		"кроме: vpn-1",
		"52.84.12.0/24",
		"*.telemetry.example",
		"--- SSH ---",
		"действие: разрешить",
		"направление: вход",
		"локальный порт: 22",
		"серверы: все",
		"срок: навсегда",
		"--- служебные · порт монитора (руками не трогать) ---",
		"порт: 8443",
		"10.0.0.0/8",
		"серверы: монитор",
		"монитор · /usr/sbin/sshd · uid=33",
	} {
		if !strings.Contains(txt, want) {
			t.Fatal("missing", want, "\n", txt)
		}
	}
	if strings.Contains(txt, "\r") {
		t.Fatal("CR in dump")
	}
}
