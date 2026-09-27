package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"netmonitor/internal/store"
)

func alertOp(t *testing.T, s *Server, id, op string, want int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id": id, "op": op})
	w := httptest.NewRecorder()
	s.handleAlert(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))
	if w.Code != want {
		t.Fatalf("%s %s: %d %s", op, id, w.Code, w.Body.String())
	}
}

func feed(t *testing.T, s *Server) map[string]uiAlert {
	t.Helper()
	out := map[string]uiAlert{}
	for _, a := range s.uiState("", "policy").Alerts {
		out[a.Rule+"/"+a.HostID] = a
	}
	return out
}

// Агент молчит 2 минуты — красная; вернулся — тревога снята сама, жёлтая,
// пока админ не закрыл карточку; закрыл — зелёная. В журнале оба шага.
func TestSilentAgentAlertLifecycle(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`UPDATE hosts SET hostname='dev-redis', last_seen_ms=? WHERE host_id='h'`, now-silentAfterMS-1000); err != nil {
		t.Fatal(err)
	}
	if err := s.sweepAlerts(now); err != nil {
		t.Fatal(err)
	}
	a := feed(t, s)["silent/h"]
	if a.State != "red" || a.Text != "dev-redis — агент молчит" {
		t.Fatalf("молчание: %+v", a)
	}
	// Минута тишины — ещё не повод.
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, now-60_000)
	if err := s.sweepAlerts(now); err != nil {
		t.Fatal(err)
	}
	a = feed(t, s)["silent/h"]
	if a.State != "yellow" || a.CloseText != "агент снова на связи" {
		t.Fatalf("вернулся: %+v", a)
	}
	alertOp(t, s, a.ID, "seen", 200)
	if a = feed(t, s)["silent/h"]; a.State != "green" {
		t.Fatalf("видел: %+v", a)
	}
	var n int
	s.st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('тревога: dev-redis — агент молчит','тревога закрыта: агент снова на связи')`).Scan(&n)
	if n != 2 {
		t.Fatalf("журнал: %d", n)
	}
	// Видел, пока была красной, — закрылась сама уже зелёной.
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, now-silentAfterMS-1000)
	s.sweepAlerts(now + 1)
	a = feed(t, s)["silent/h"]
	alertOp(t, s, a.ID, "seen", 200)
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, now)
	s.sweepAlerts(now + 2)
	if a = feed(t, s)["silent/h"]; a.State != "green" {
		t.Fatalf("видел до закрытия: %+v", a)
	}
}

func TestPolicyFailAlert(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET last_seen_ms=? WHERE host_id='h'`, now)
	s.st.DB.Exec(`INSERT INTO settings(k,v) VALUES('fw_status:a', ?)`, `{"applied_rev":3,"error":"nft: syntax error"}`)
	if err := s.sweepAlerts(now); err != nil {
		t.Fatal(err)
	}
	a := feed(t, s)["policy-fail/h"]
	if a.State != "red" || !strings.Contains(a.Text, "политика не применилась: nft: syntax error") {
		t.Fatalf("%+v", a)
	}
	s.st.DB.Exec(`UPDATE settings SET v=? WHERE k='fw_status:a'`, `{"applied_rev":4}`)
	s.sweepAlerts(now)
	if a = feed(t, s)["policy-fail/h"]; a.State != "yellow" || a.CloseText != "политика применилась" {
		t.Fatalf("%+v", a)
	}
}

// Шторм — при любом режиме: агент в обучении получает «learn+storm», в
// карточке «не снимать» глушит, «снять шторм» снимает сразу.
func TestStormAnyModeAndCardActions(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error {
		for i := 0; i < stormLevel["ssh"]; i++ {
			if _, err := tx.Exec(`INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms,host_id)
				VALUES(?,'host',?,zeroblob(16),'both','active','перебор SSH','ssh','auto',?,'h')`, "s"+string(rune('A'+i)), "203.0.113."+string(rune('0'+i%10)), now); err != nil {
				return err
			}
		}
		return stormCheck(tx, "h", "ssh", now)
	}); err != nil {
		t.Fatal(err)
	}
	res, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "learn+storm" {
		t.Fatalf("режим в шторм: %q", res.Mode)
	}
	a := feed(t, s)["storm/h"]
	if a.State != "red" {
		t.Fatalf("%+v", a)
	}
	alertOp(t, s, a.ID, "keep", 200)
	if a = feed(t, s)["storm/h"]; a.State != "red" || !a.Seen {
		t.Fatalf("не снимать: %+v", a)
	}
	alertOp(t, s, a.ID, "open", 200)
	if a = feed(t, s)["storm/h"]; a.State != "green" || a.CloseText != "снял шторм" {
		t.Fatalf("снять шторм: %+v", a)
	}
	if res, _ = s.pollSnapshot("a", "trusted", 0); res.Mode != "learn" {
		t.Fatalf("после открытия: %q", res.Mode)
	}
	alertOp(t, s, a.ID, "open", 400)
}

// Лестница растёт сама; тревога — только когда адрес вернулся после 7 суток.
func TestPersistOnlyAfterLadderExhausted(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	ban := func() {
		if err := s.st.Update(func(tx *sql.Tx) error {
			return banInTx(tx, "203.0.113.77", "h", false, "перебор SSH", "ssh", now)
		}); err != nil {
			t.Fatal(err)
		}
		s.st.DB.Exec(`UPDATE blocks SET state='expired' WHERE remote_ip='203.0.113.77' AND state='active'`)
	}
	for i := 0; i < len(ladder); i++ {
		ban()
		var n int
		s.st.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE rule_id='persist'`).Scan(&n)
		if n != 0 {
			t.Fatalf("ступень %d: тревога раньше времени", i)
		}
	}
	ban()
	if a := feed(t, s)["persist/h"]; a.State != "red" || a.Text != "203.0.113.77 — вернулся после бана на 7 суток" {
		t.Fatalf("%+v", a)
	}
}
