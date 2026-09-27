package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"netmonitor/internal/policy"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func banRequest(t *testing.T, s *Server, body string, want int) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleUIBlock(w, httptest.NewRequest("POST", "/ui/api/block", bytes.NewBufferString(body)))
	if w.Code != want {
		t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if want == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return out.ID
}

func unbanRequest(t *testing.T, s *Server, body string, want int) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleUIUnblock(w, httptest.NewRequest("POST", "/ui/api/unblock", bytes.NewBufferString(body)))
	if w.Code != want {
		t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
	}
}

// park adds two more trusted servers to the single-agent fixture.
func park(t *testing.T, s *Server) {
	t.Helper()
	if _, err := s.st.DB.Exec("INSERT INTO hosts(host_id) VALUES('h2'),('h3')"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec("INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a2','h2','fp2','trusted',1),('a3','h3','fp3','trusted',1)"); err != nil {
		t.Fatal(err)
	}
}

func blockOf(t *testing.T, s *Server, agent, id string) protocol.BlockView {
	t.Helper()
	res, err := s.pollSnapshot(agent, "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Blocks {
		if b.BlockID == id {
			return b
		}
	}
	return protocol.BlockView{}
}

func TestManualBanKeepsTargetAndScope(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	id := banRequest(t, s, `{"ip":"203.0.113.9","proto":"tcp","direction":"in","port":22,"hosts":["h","h2"],"ttl":"1h"}`, 200)
	for _, agent := range []string{"a", "a2"} {
		b := blockOf(t, s, agent, id)
		if b.RemoteIP != "203.0.113.9" || b.Protocol != "tcp" || b.Port != 22 || b.Direction != "in" || b.ExpiresAt == 0 {
			t.Fatalf("condition lost on %s: %+v", agent, b)
		}
	}
	if b := blockOf(t, s, "a3", id); b.BlockID != "" {
		t.Fatal("scope expanded to an unselected server")
	}
	rec, err := readBan(s.st.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	now := store.NowMS()
	hit := policy.Contact{Direction: "in", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 22}
	if d, ok := policy.Evaluate([]policy.Rule{rec.rule()}, "h", hit, now); !ok || d.Action != "deny" {
		t.Fatal("ban does not deny its own target")
	}
	for _, c := range []policy.Contact{
		{Direction: "in", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443},
		{Direction: "in", Protocol: "udp", RemoteIP: "203.0.113.9", RemotePort: 22},
		{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 22},
		{Direction: "in", Protocol: "tcp", RemoteIP: "203.0.113.10", RemotePort: 22},
	} {
		if _, ok := policy.Evaluate([]policy.Rule{rec.rule()}, "h", c, now); ok {
			t.Fatalf("ban widened to %+v", c)
		}
	}
	banRequest(t, s, `{"ip":"203.0.113.9","hosts":[]}`, 400)
	banRequest(t, s, `{"ip":"203.0.113.9","hosts":["nosuch"]}`, 400)
	banRequest(t, s, `{"ip":"10.0.0.0/8"}`, 400)
	banRequest(t, s, `{"proto":"tcp"}`, 400)
	banRequest(t, s, `{"ip":"203.0.113.9","port":22}`, 400)
}

// A local port is closed only by hand, with an explicit confirmation and a term.
func TestLocalPortBanNeedsConfirmationAndTerm(t *testing.T) {
	s, _ := batchFixture(t)
	banRequest(t, s, `{"proto":"tcp","local_port":8080,"direction":"in","ttl":"1h"}`, 400)
	banRequest(t, s, `{"proto":"tcp","local_port":8080,"direction":"in","confirm_local_port":true,"forever":true}`, 400)
	id := banRequest(t, s, `{"proto":"tcp","local_port":8080,"direction":"in","confirm_local_port":true,"ttl":"1h"}`, 200)
	b := blockOf(t, s, "a", id)
	if b.LocalPort != 8080 || b.RemoteIP != "" || b.Protocol != "tcp" || b.Direction != "in" {
		t.Fatalf("local port ban lost its target: %+v", b)
	}
	auto := banSpec{LocalPort: 8080, Protocol: "tcp", Direction: "in", Source: "scan", ExpiresAt: store.NowMS() + 1000}
	if err := validateBan(auto, true); err == nil {
		t.Fatal("automation closed a local port")
	}
	forever := banSpec{RemoteIP: "203.0.113.9", Source: "scan"}
	if err := validateBan(forever, false); err == nil {
		t.Fatal("automatic ban became permanent")
	}
}

func TestBanOperationsAddressOneBanAtATime(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	wide := banRequest(t, s, `{"ip":"203.0.113.9","ttl":"1h"}`, 200)
	narrow := banRequest(t, s, `{"ip":"203.0.113.9","proto":"tcp","port":22,"hosts":["h2"],"ttl":"1h"}`, 200)
	unbanRequest(t, s, `{"id":"`+narrow+`"}`, 200)
	if b := blockOf(t, s, "a", wide); b.BlockID == "" {
		t.Fatal("lifting one ban removed the other on the same address")
	}
	if b := blockOf(t, s, "a2", narrow); b.BlockID != "" {
		t.Fatal("lifted ban still applies")
	}
	unbanRequest(t, s, `{"id":"`+narrow+`"}`, 400)
	unbanRequest(t, s, `{"id":"unknown"}`, 400)

	before := blockOf(t, s, "a", wide).ExpiresAt
	raw, _ := json.Marshal(map[string]any{"id": wide, "ip": "203.0.113.9", "until_ms": before + 3600000, "hosts": []string{"h", "h3"}})
	banRequest(t, s, string(raw), 200)
	if got := blockOf(t, s, "a", wide).ExpiresAt; got != before+3600000 {
		t.Fatalf("extension not stored: %d", got)
	}
	if b := blockOf(t, s, "a2", wide); b.BlockID != "" {
		t.Fatal("server removed from scope still receives the ban")
	}
	if b := blockOf(t, s, "a3", wide); b.BlockID == "" {
		t.Fatal("server added to scope did not receive the ban")
	}
	unbanRequest(t, s, `{"id":"`+wide+`"}`, 200)
	unbanRequest(t, s, `{"ip":"203.0.113.9"}`, 400)
}

// «применено N из M» counts acknowledgements, and a changed ban is confirmed anew.
func TestBanAppliedCountsOnlyConfirmedAgents(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	id := banRequest(t, s, `{"ip":"203.0.113.9","hosts":["h","h2"],"ttl":"1h"}`, 200)
	rec, err := readBan(s.st.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	applied, total, err := banApplied(s.st.DB, rec)
	if err != nil || applied != 0 || total != 2 {
		t.Fatalf("applied=%d total=%d err=%v", applied, total, err)
	}
	confirm(t, s, "a")
	rec, _ = readBan(s.st.DB, id)
	if applied, total, err = banApplied(s.st.DB, rec); err != nil || applied != 1 || total != 2 {
		t.Fatalf("applied=%d total=%d err=%v", applied, total, err)
	}
	raw, _ := json.Marshal(map[string]any{"id": id, "ip": "203.0.113.9", "hosts": []string{"h", "h2"}, "until_ms": store.NowMS() + 7200000})
	banRequest(t, s, string(raw), 200)
	rec, _ = readBan(s.st.DB, id)
	if applied, _, err = banApplied(s.st.DB, rec); err != nil || applied != 0 {
		t.Fatalf("stale confirmation survived a change: applied=%d err=%v", applied, err)
	}
}

// confirm plays a full poll cycle: take the commands, then acknowledge them.
func confirm(t *testing.T, s *Server, agent string) {
	t.Helper()
	res, err := s.pollSnapshot(agent, "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range res.Commands {
		ids = append(ids, c.ID)
	}
	rev := res.PolicyRev
	if err := s.recordApply(agent, protocol.PollReq{
		Rev: rev, Ack: ids,
		Status: &protocol.ApplyStatus{Backend: "nftables", DesiredRev: rev, AppliedRev: &rev, CommandIDs: ids},
	}); err != nil {
		t.Fatal(err)
	}
}

// The ban list shows the stored target, the real scope and the confirmation.
func TestBanViewCarriesTargetScopeAndConfirmation(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	id := banRequest(t, s, `{"ip":"203.0.113.9","proto":"tcp","port":443,"direction":"out","hosts":["h","h2"],"ttl":"1h"}`, 200)
	confirm(t, s, "a")
	st := s.uiState("", "policy")
	if st.err != nil {
		t.Fatal(st.err)
	}
	if len(st.Bans) != 1 {
		t.Fatalf("bans=%d", len(st.Bans))
	}
	b := st.Bans[0]
	if b.ID != id || b.IP != "203.0.113.9" || b.Port != 443 || b.Protocol != "tcp" || b.Direction != "out" {
		t.Fatalf("target lost: %+v", b)
	}
	if b.Target != "203.0.113.9:443/tcp · исход" {
		t.Fatalf("target label %q", b.Target)
	}
	if string(b.Hosts) != `["h","h2"]` || b.Applied != 1 || b.Total != 2 {
		t.Fatalf("scope or confirmation wrong: %s %d/%d", b.Hosts, b.Applied, b.Total)
	}
	if b.Until == "навсегда" || b.UntilMS == 0 {
		t.Fatalf("expiry lost: %q", b.Until)
	}
	if len(b.Missed) == 0 {
		t.Fatal("missed hosts omitted")
	}
}

func TestBanPauseAndAutobanRespectScope(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	id := banRequest(t, s, `{"ip":"203.0.113.9","hosts":["h2"],"ttl":"1h"}`, 200)
	// A server may not pause a ban that never reached it.
	if err := s.pauseBlocks("a", protocol.LocalUnblock{RequestID: "r1", BlockIDs: []string{id}, Reason: "rollback"}); err != nil {
		t.Fatal(err)
	}
	var paused int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM block_pause").Scan(&paused)
	if paused != 0 {
		t.Fatal("paused a ban outside the scope")
	}
	if err := s.pauseBlocks("a2", protocol.LocalUnblock{RequestID: "r2", BlockIDs: []string{id}, Reason: "rollback"}); err != nil {
		t.Fatal(err)
	}
	if b := blockOf(t, s, "a2", id); b.BlockID != "" {
		t.Fatal("paused ban still delivered")
	}
	// An SSH ban on one server does not silence the detector on another.
	now := store.NowMS()
	err := s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "203.0.113.77", "h", false, "перебор SSH", "ssh", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "203.0.113.77", "h3", false, "перебор SSH", "ssh", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM blocks WHERE remote_ip='203.0.113.77' AND state='active'").Scan(&n)
	if n != 2 {
		t.Fatalf("independent servers shared one ban: %d", n)
	}
	err = s.st.Update(func(tx *sql.Tx) error {
		return banInTx(tx, "203.0.113.77", "h", false, "перебор SSH", "ssh", now)
	})
	if err != nil {
		t.Fatal(err)
	}
	s.st.DB.QueryRow("SELECT COUNT(*) FROM blocks WHERE remote_ip='203.0.113.77' AND state='active'").Scan(&n)
	if n != 2 {
		t.Fatalf("repeat created a second ban for the same server: %d", n)
	}
}

// A receipt belongs to a ban revision, including changes in the same millisecond.
func TestBanConfirmationRevisionAndLateJoin(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	b := banSpec{RemoteIP: "203.0.113.99", Source: "manual", CreatedBy: "adm", ExpiresAt: now + 3600000}
	if err := s.st.Update(func(tx *sql.Tx) error {
		var err error
		b.ID, err = writeBan(tx, b, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	confirm(t, s, "a")
	b.ExpiresAt += 3600000
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := writeBan(tx, b, now); return err }); err != nil {
		t.Fatal(err)
	}
	rec, _ := readBan(s.st.DB, b.ID)
	if n, _, err := banApplied(s.st.DB, rec); err != nil || n != 0 {
		t.Fatalf("old receipt survived same-ms change: %d %v", n, err)
	}
	confirm(t, s, "a")
	park(t, s)
	confirm(t, s, "a2")
	rec, _ = readBan(s.st.DB, b.ID)
	if n, total, err := banApplied(s.st.DB, rec); err != nil || n != 2 || total != 3 {
		t.Fatalf("late join not confirmed: %d/%d %v", n, total, err)
	}
	if err := s.pauseBlocks("a", protocol.LocalUnblock{RequestID: "local", BlockIDs: []string{b.ID}, Reason: "rollback"}); err != nil {
		t.Fatal(err)
	}
	confirm(t, s, "a")
	if n, total, err := banApplied(s.st.DB, rec); err != nil || n != 1 || total != 3 {
		t.Fatalf("locally lifted ban counted: %d/%d %v", n, total, err)
	}
}

func TestNarrowManualBanDoesNotSuppressAutoban(t *testing.T) {
	s, _ := batchFixture(t)
	banRequest(t, s, `{"ip":"203.0.113.99","proto":"tcp","port":443,"direction":"out","ttl":"1h"}`, 200)
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error { return banInTx(tx, "203.0.113.99", "h", false, "SSH", "ssh", now) }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.st.DB.QueryRow("SELECT COUNT(*) FROM blocks WHERE source='ssh'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("narrow ban suppressed SSH: %d %v", n, err)
	}
}

func TestBanAPIRejectsAmbiguousUnblockAndInvalidLifetime(t *testing.T) {
	s, _ := batchFixture(t)
	// Use the actual fixture directory: the old test accidentally opened a
	// second empty database and passed even though IP-based bulk removal worked.
	s.cfg.DataDir = filepath.Dir(s.st.Path())
	id := banRequest(t, s, `{"ip":"203.0.113.99","ttl":"1h"}`, 200)
	unbanRequest(t, s, `{"ip":"203.0.113.99"}`, 400)
	if blockOf(t, s, "a", id).BlockID == "" {
		t.Fatal("ambiguous API removed ban")
	}
	for _, body := range []string{
		`{"ip":"203.0.113.99","ttl":"-1h"}`,
		`{"ip":"203.0.113.99","ttl":"nonsense"}`,
		`{"ip":"203.0.113.99","until_ms":-1}`,
	} {
		banRequest(t, s, body, 400)
	}
	now := store.NowMS()
	if err := s.st.Update(func(tx *sql.Tx) error { return banInTx(tx, "203.0.113.98", "h", false, "SSH", "ssh", now) }); err != nil {
		t.Fatal(err)
	}
	var auto string
	if err := s.st.DB.QueryRow("SELECT block_id FROM blocks WHERE source='ssh'").Scan(&auto); err != nil {
		t.Fatal(err)
	}
	banRequest(t, s, `{"id":"`+auto+`","ip":"203.0.113.98","forever":true}`, 400)
}

func TestBanACKCannotConfirmEarlierSnapshot(t *testing.T) {
	s, _ := batchFixture(t)
	banRequest(t, s, `{"ip":"203.0.113.99","ttl":"1h"}`, 200)
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range pr.Commands {
		ids = append(ids, c.ID)
	}
	old := pr.PolicyRev - 1
	err = s.recordApply("a", protocol.PollReq{Ack: ids, Status: &protocol.ApplyStatus{Backend: "nftables", DesiredRev: old, AppliedRev: &old, CommandIDs: ids}})
	if err == nil {
		t.Fatal("old snapshot confirmed newer ban commands")
	}
}

// Ответили на тревогу — она уходит из плитки: меню больше не мигает, сирена
// молчит. «Бан сняли руками» ждёт своего ответа «вернуть бан».
func TestBanClosesAddressAlerts(t *testing.T) {
	s, _ := batchFixture(t)
	park(t, s)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,severity,summary)
		VALUES('c1','scan-cap',1,'h','scan-cap/h',?,'high','слишком много сканов'),
		('c2','persist',1,'h','persist/h/203.0.113.88',?,'high','вернулся после бана'),
		('c3','ssh-cap',1,'h2','ssh-cap/h2',?,'high','шквал по SSH'),
		('c4','paused_local',1,'h','paused_local/h',?,'high','бан снят руками')`, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO alert_refs(alert_id,ref_kind,ref_id) VALUES
		('c1','ip','203.0.113.50'),('c2','ip','203.0.113.88'),('c3','ip','203.0.113.50'),('c4','ip','203.0.113.50')`); err != nil {
		t.Fatal(err)
	}
	banRequest(t, s, `{"ip":"203.0.113.50","hosts":["h"],"ttl":"1h"}`, 200)
	open := func(id string) bool {
		var n int
		if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE alert_id=? AND closed_at_ms IS NULL`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if open("c1") {
		t.Fatal("тревога про забаненный адрес осталась живой")
	}
	if !open("c2") {
		t.Fatal("закрыли тревогу про другой адрес")
	}
	if !open("c3") {
		t.Fatal("закрыли тревогу на сервере, который бан не покрывает")
	}
	if !open("c4") {
		t.Fatal("«бан снят руками» закрыт не своим ответом")
	}
	var n int
	if err := s.st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='тревога закрыта: забанил' AND object='c1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("в журнале %d записей о закрытии", n)
	}
	// Ответ админа — сразу зелёная, «видел» не нужен.
	var by, note string
	var seen sql.NullInt64
	if err := s.st.DB.QueryRow(`SELECT COALESCE(closed_by,''), COALESCE(close_note,''), seen_at_ms FROM alerts WHERE alert_id='c1'`).Scan(&by, &note, &seen); err != nil {
		t.Fatal(err)
	}
	if by != "adm" || note != "забанил" || !seen.Valid {
		t.Fatalf("закрытие: by=%q note=%q seen=%v", by, note, seen.Valid)
	}
	// Продление бана на весь парк снимает и тревогу соседнего сервера.
	id := banRequest(t, s, `{"ip":"203.0.113.50","ttl":"6h"}`, 200)
	if id == "" || open("c3") {
		t.Fatal("бан на все серверы не закрыл тревогу соседнего")
	}
	// «Вернулся после 7 суток» закрывает только бан навсегда.
	banRequest(t, s, `{"ip":"203.0.113.88","ttl":"6h"}`, 200)
	if !open("c2") {
		t.Fatal("срочный бан закрыл «вернулся после 7 суток»")
	}
	banRequest(t, s, `{"ip":"203.0.113.88","ttl":"forever"}`, 200)
	if open("c2") {
		t.Fatal("бан навсегда не закрыл «вернулся после 7 суток»")
	}
}
