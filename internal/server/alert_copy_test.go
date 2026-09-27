package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func TestAlertEventText(t *testing.T) {
	cases := []struct {
		a    uiAlert
		host string
		want string
	}{
		{uiAlert{Rule: "scan-cap", Addr: "185.234.52.11"}, "", "185.234.52.11 — слишком много сканов"},
		{uiAlert{Rule: "ssh-cap", Text: "SSH: потолок 20/мин, правило не банит 198.51.100.9"}, "", "198.51.100.9 — шквал по SSH"},
		{uiAlert{Rule: "persist", Addr: "203.0.113.88"}, "", "203.0.113.88 — вернулся после бана на 7 суток"},
		{uiAlert{Rule: "paused_local", Addr: "185.234.52.11"}, "dev-postgres", "185.234.52.11 — бан снят руками на dev-postgres"},
		{uiAlert{Rule: "clone", Addr: "10.0.0.5", Text: "клон сертификата с 10.0.0.5"}, "dev-redis", "dev-redis — чужая копия ключа с 10.0.0.5"},
		{uiAlert{Rule: "disk-90"}, "монитор", "диск 90% — трафик не пишется"},
		{uiAlert{Rule: "storm", Text: "шторм по SSH — новые входы с улицы закрыты"}, "", "шторм SSH"},
		{uiAlert{Rule: "storm", Text: "шторм сканов — новые входы с улицы закрыты"}, "", "шторм сканов"},
	}
	for _, c := range cases {
		if got := alertEventText(c.a, c.host); got != c.want {
			t.Fatalf("%s: got %q want %q", c.a.Rule, got, c.want)
		}
	}
}

func TestListUIAlertsPolishesCopyAndRefs(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,severity,summary)
		VALUES('a1','scan-cap',1,'h','scan-cap/h',?,'high','скан: потолок 200/мин, правило не банит'),
		('a2','paused_local',1,'h','paused_local/h',?,'high','с консоли сервера сняли бан 185.234.52.11 — на этот сервер монитор его больше не ставит'),
		('a3','persist',1,'h','persist/h/203.0.113.88',?,'high','настойчивый: скан портов 203.0.113.88')`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO alert_refs(alert_id,ref_kind,ref_id) VALUES('a1','ip','45.33.32.156'),('a2','ip','185.234.52.11'),('a3','ip','203.0.113.88')`); err != nil {
		t.Fatal(err)
	}
	st := s.uiState("", "policy")
	got := map[string]uiAlert{}
	for _, a := range st.Alerts {
		got[a.ID] = a
	}
	if got["a1"].Text != "45.33.32.156 — слишком много сканов" || got["a1"].Addr != "45.33.32.156" {
		t.Fatalf("scan-cap %+v", got["a1"])
	}
	if got["a2"].Text != "185.234.52.11 — бан снят руками на dev-postgres" {
		t.Fatalf("paused %+v", got["a2"])
	}
	if got["a3"].Text != "203.0.113.88 — вернулся после бана на 7 суток" {
		t.Fatalf("persist %+v", got["a3"])
	}
}

func TestAlertCloseTextStorm(t *testing.T) {
	if got := alertCloseText("adm", "открыл вход"); got != "снял шторм" {
		t.Fatalf("old open: %q", got)
	}
	if got := alertCloseText("auto", "шторм стих, вход открыт"); got != "шторм стих" {
		t.Fatalf("old auto: %q", got)
	}
}

func TestAlertHintShort(t *testing.T) {
	h := alertHint("storm", false)
	if strings.Contains(h, "улиц") || strings.Contains(h, "вход") || strings.Contains(h, " ты") || strings.Contains(h, "ты ") {
		t.Fatalf("hint %q", h)
	}
	if len([]rune(h)) > 120 {
		t.Fatalf("too long %d %q", len([]rune(h)), h)
	}
}

func TestRestorePausedBanFromAlert(t *testing.T) {
	s, _ := batchFixture(t)
	if _, err := s.st.DB.Exec(`INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms)
		VALUES('b','all','198.18.0.2',zeroblob(16),'both','active','скан портов','scan','auto',1)`); err != nil {
		t.Fatal(err)
	}
	req := protocol.LocalUnblock{RequestID: "r1", BlockIDs: []string{"b"}, Reason: "rollback"}
	if err := s.pauseBlocks("a", req); err != nil {
		t.Fatal(err)
	}
	if b := blockOf(t, s, "a", "b"); b.BlockID != "" {
		t.Fatal("paused ban still delivered")
	}
	st := s.uiState("", "policy")
	var alert uiAlert
	for _, a := range st.Alerts {
		if a.Rule == "paused_local" {
			alert = a
		}
	}
	if alert.ID == "" || alert.Addr != "198.18.0.2" {
		t.Fatalf("pause alert %+v", st.Alerts)
	}
	foundPaused := false
	for _, b := range st.Bans {
		if b.ID == "b" {
			for _, h := range b.Paused {
				if h == "h" {
					foundPaused = true
				}
			}
		}
	}
	if !foundPaused {
		t.Fatalf("paused mark missing: %+v", st.Bans)
	}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"id": alert.ID, "op": "restore"})
	s.handleAlert(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var n, paused int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM block_pause`).Scan(&paused)
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE alert_id=? AND closed_at_ms IS NULL`, alert.ID).Scan(&n)
	if paused != 0 || n != 0 {
		t.Fatal("still paused", paused, n)
	}
	if b := blockOf(t, s, "a", "b"); b.BlockID != "b" {
		t.Fatal("ban not returned to agent")
	}
}
