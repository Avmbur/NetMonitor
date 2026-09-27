package server

import (
	"testing"

	"netmonitor/internal/store"
)

func TestPolishAuditHidesIDsAndJSON(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`UPDATE agents SET display_name='dev-postgres' WHERE agent_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO policy_rules(rule_id,version,sort_order,payload) VALUES('rule-1',1,1,?)`, `{"id":"rule-1","name":"SSH","action":"allow"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO ip_groups(group_id,name,policy,created_at_ms) VALUES('g1','телеметрия','block',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,proc_comm,status)
		VALUES('q1','h','k',?,1,?,'out','tcp','203.0.113.9',443,'curl','open')`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.DB.Exec(`INSERT INTO alerts(alert_id,rule_id,rule_version,host_id,dedup_key,opened_at_ms,severity,summary)
		VALUES('al1','clone',1,'h','clone/h',?,'high','клон сертификата с 192.168.10.184')`, now); err != nil {
		t.Fatal(err)
	}
	db := &checkedRead{db: s.st.DB}
	cases := []struct{ actor, action, object, detail, src, wantActor, wantAction, wantObject string }{
		{"adm", "вход", "", "", "192.168.10.50", "adm", "вход", "с 192.168.10.50"},
		{"adm", "управление сервером: mode", "h", `{"mode":"learn","quarantine":false}`, "", "adm", "сменил режим", "dev-postgres · обучение"},
		{"adm", "управление сервером: quarantine", "h", `{"quarantine":true}`, "", "adm", "включил карантин", "dev-postgres"},
		{"adm", "снял вопрос", "q1", "", "", "adm", "снял вопрос", "dev-postgres · curl · 203.0.113.9:443"},
		{"adm", "убрал тревогу в историю", "al1", "", "", "adm", "убрал тревогу в историю", "клон сертификата с 192.168.10.184"},
		{"adm", "правило: ", "rule-1", "", "", "adm", "сохранил правило", "SSH"},
		{"adm", "правило: delete", "rule-1", "", "", "adm", "удалил правило", "SSH"},
		{"adm", "группа: member", "g1", "", "", "adm", "добавил в группу", "телеметрия"},
		{"auto", "перебор SSH", "192.168.10.184", "ssh", "", "автомат", "перебор SSH", "192.168.10.184"},
		{"a", "восстановлен firewall", "h", "", "", "dev-postgres", "восстановил firewall", "dev-postgres"},
		{"adm", "правило: delete", "01234567-89ab-7cde-8f01-23456789abcd", "", "", "adm", "удалил правило", "удалённое правило"},
	}
	for _, c := range cases {
		ga, gn, goj := polishAudit(db, c.actor, c.action, c.object, c.detail, c.src)
		if ga != c.wantActor || gn != c.wantAction || goj != c.wantObject {
			t.Fatalf("%q / %q => actor=%q action=%q object=%q want %q / %q / %q",
				c.action, c.object, ga, gn, goj, c.wantActor, c.wantAction, c.wantObject)
		}
	}
}

func TestReadUIAuditKindsAndWho(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	rows := []struct{ actor, action string }{
		{"adm", "забанил"},
		{"auto", "скан портов"},
		{"auto", "шторм: внешние подключения закрыты"},
		{"adm", "убрал тревогу в историю"},
		{"auto", "тревога закрыта: адрес забанен"},
		{"adm", "управление сервером: pause"},
		{"a", "восстановлен firewall"},
		{"adm", "сменил пароль"},
		{"adm", "вход"},
	}
	for i, r := range rows {
		if _, err := s.st.DB.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,'')`,
			"k"+string(rune('0'+i)), now+int64(i), r.actor, r.action); err != nil {
			t.Fatal(err)
		}
	}
	db := &checkedRead{db: s.st.DB}
	count := func(action, who string) int {
		return len(readUIAudit(db, stateQuery{Action: action, Who: who}))
	}
	cases := []struct {
		action, who string
		want        int
	}{
		{"ban", "", 2},
		{"ban", "auto", 1},
		{"alert", "", 2},
		{"storm", "", 1},
		{"mode", "", 1},
		{"firewall", "", 1},
		{"settings", "", 1},
		{"login", "", 1},
		{"", "me", 5},
		{"", "auto", 4},
		{"пароль", "", 1},
	}
	for _, c := range cases {
		if got := count(c.action, c.who); got != c.want {
			t.Fatalf("action=%q who=%q: %d записей, want %d", c.action, c.who, got, c.want)
		}
	}
}

func TestReadUIAuditFormatsControlJSON(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	s.st.DB.Exec(`UPDATE hosts SET hostname='dev-postgres' WHERE host_id='h'`)
	_, err := s.st.DB.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object,detail)
		VALUES('x',?,'adm','управление сервером: pause','h',?)`, now, `{"mode":"park","quarantine":false,"pause_until":1}`)
	if err != nil {
		t.Fatal(err)
	}
	st := s.uiState("", "log")
	if len(st.Audit) == 0 {
		t.Fatal("empty")
	}
	a := st.Audit[0]
	if a.Action != "пауза авто-банов" || a.Object != "dev-postgres" {
		t.Fatalf("%+v", a)
	}
}
