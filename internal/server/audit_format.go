package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode"

	"netmonitor/internal/policy"
)

// Пункты «действие» в фильтре журнала. Условия — по сырому action в
// audit_log: подпись в морде собирает polishAudit уже после выборки.
var auditKinds = map[string]string{
	"ban":      `action IN ('забанил','изменил бан','снял бан','вернул бан','бан снят на сервере','скан портов','перебор SSH')`,
	"agent":    `action IN ('подтвердил агента','отклонил агента','отозвал сертификат','удалил агента','забыл агента','запросил снятие агента','снял агента с сервера','запросил обновление монитора','запросил обновление агентов','обновил агента','карантин клона')`,
	"group":    `action='сохранил группу' OR action LIKE 'группа:%'`,
	"alert":    `action LIKE '%тревог%'`,
	"rule":     `action LIKE 'правило:%'`,
	"question": `action='снял вопрос'`,
	"mode":     `action LIKE 'управление сервером:%'`,
	"never":    `action LIKE '%не блокировать'`,
	"storm":    `action LIKE 'шторм%'`,
	"login":    `action='вход'`,
	"settings": `action IN ('сохранил настройки','сменил пароль','снял снимок БД')`,
	"firewall": `action IN ('восстановлен firewall','бан снят на сервере')`,
}

// Руками — из морды или nmctl; остальное сделал монитор или агент сам.
const auditByAdmin = `COALESCE(actor,'') IN ('','adm','cli')`

func looksAuditID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func stripJSON(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s[0] == '{' || s[0] == '[' {
		return ""
	}
	if i := strings.Index(s, " · {"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, " · ["); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func firstToken(s string) (head, rest string) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, unicode.IsSpace)
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}

func peekName(db *checkedRead, q string, args ...any) string {
	if db == nil || db.db == nil {
		return ""
	}
	var name string
	if err := db.db.QueryRow(q, args...).Scan(&name); err != nil || strings.TrimSpace(name) == "" {
		return ""
	}
	return strings.TrimSpace(name)
}

func auditHostName(db *checkedRead, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if name := peekName(db, `SELECT COALESCE(NULLIF(a.display_name,''), NULLIF(h.hostname,''), a.host_id)
		FROM agents a LEFT JOIN hosts h ON h.host_id=a.host_id
		WHERE a.host_id=? OR a.agent_id=? LIMIT 1`, id, id); name != "" {
		return name
	}
	if name := peekName(db, `SELECT COALESCE(NULLIF(hostname,''), host_id) FROM hosts WHERE host_id=?`, id); name != "" {
		return name
	}
	return id
}

func auditRuleName(db *checkedRead, id string) string {
	raw := peekName(db, `SELECT payload FROM policy_rules WHERE rule_id=?`, id)
	if raw == "" {
		return id
	}
	var r policy.Rule
	if json.Unmarshal([]byte(raw), &r) != nil || strings.TrimSpace(r.Name) == "" {
		return id
	}
	return r.Name
}

func auditGroupName(db *checkedRead, id string) string {
	if name := peekName(db, `SELECT name FROM ip_groups WHERE group_id=?`, id); name != "" {
		return name
	}
	return id
}

func auditQuestionLabel(db *checkedRead, id string) string {
	if db == nil || db.db == nil {
		return id
	}
	var host, proc, ip string
	var port int
	err := db.db.QueryRow(`SELECT COALESCE(NULLIF(h.hostname,''), q.host_id), COALESCE(NULLIF(q.proc_comm,''),'—'), COALESCE(q.remote_ip,''), COALESCE(q.remote_port,0)
		FROM learn_questions q LEFT JOIN hosts h ON h.host_id=q.host_id WHERE q.question_id=?`, id).Scan(&host, &proc, &ip, &port)
	if err != nil {
		return id
	}
	dest := ip
	if port > 0 && dest != "" {
		dest += ":" + strconv.Itoa(port)
	}
	return strings.Join(nonempty(host, proc, dest), " · ")
}

func auditAlertLabel(db *checkedRead, id string) string {
	if name := peekName(db, `SELECT summary FROM alerts WHERE alert_id=?`, id); name != "" {
		return name
	}
	return id
}

func nonempty(parts ...string) []string {
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func polishAuditActor(db *checkedRead, actor string) string {
	actor = strings.TrimSpace(actor)
	switch {
	case actor == "" || actor == "adm":
		return "adm"
	case actor == "auto":
		return "автомат"
	case actor == "system":
		return "система"
	case strings.HasPrefix(actor, "agent:"):
		actor = strings.TrimPrefix(actor, "agent:")
	}
	if name := auditHostName(db, actor); name != "" && name != actor {
		return name
	}
	return actor
}

func formatControlAudit(op, host, detail string) (action, object string) {
	var c hostControl
	_ = json.Unmarshal([]byte(detail), &c)
	switch op {
	case "mode":
		title := map[string]string{"park": "как парк", "allow": "разрешить", "learn": "обучение", "block": "блокировать"}[c.Mode]
		if title == "" {
			title = c.Mode
		}
		if title != "" {
			return "сменил режим", strings.Join(nonempty(host, title), " · ")
		}
		return "сменил режим", host
	case "quarantine":
		if c.Quarantine {
			return "включил карантин", host
		}
		return "снял карантин", host
	case "pause":
		if c.PauseUntil > 0 {
			return "пауза авто-банов", host
		}
		return "снял паузу авто-банов", host
	default:
		return "управление сервером", host
	}
}

func polishAudit(db *checkedRead, actor, action, object, detail, src string) (string, string, string) {
	rawActor := actor
	rawDetail := detail
	actor = polishAuditActor(db, actor)
	object = stripJSON(object)
	switch {
	case action == "вход":
		if src != "" {
			object = "с " + src
		}
	case strings.HasPrefix(action, "управление сервером:"):
		op := strings.TrimSpace(strings.TrimPrefix(action, "управление сервером:"))
		host := auditHostName(db, firstOf(object))
		action, object = formatControlAudit(op, host, rawDetail)
	case action == "снял вопрос":
		object = auditQuestionLabel(db, firstOf(object))
	case action == "убрал тревогу в историю":
		object = auditAlertLabel(db, firstOf(object))
	case strings.HasPrefix(action, "тревога закрыта: ") || action == "шторм: держать вход закрытым":
		if looksAuditID(firstOf(object)) {
			object = auditAlertLabel(db, firstOf(object))
		}
	case strings.HasPrefix(action, "тревога: "):
		// Текст тревоги уже в действии; объект — её id, в морде лишний.
		object = ""
		rawDetail = ""
	case strings.HasPrefix(action, "правило:"):
		op := strings.TrimSpace(strings.TrimPrefix(action, "правило:"))
		name := auditRuleName(db, firstOf(object))
		switch op {
		case "delete":
			action = "удалил правило"
		case "однократно израсходовано":
			action = "правило израсходовано однократно"
		default:
			action = "сохранил правило"
		}
		object = name
	case strings.HasPrefix(action, "группа:"):
		op := strings.TrimSpace(strings.TrimPrefix(action, "группа:"))
		name := auditGroupName(db, firstOf(object))
		switch op {
		case "member":
			action = "добавил в группу"
		case "delete":
			action = "удалил группу"
		case "order":
			action = "изменил порядок групп"
			name = ""
		default:
			action = "изменил группу"
		}
		object = name
	case action == "сохранил группу":
		object = auditGroupName(db, firstOf(object))
	case action == "восстановлен firewall":
		action = "восстановил firewall"
		object = auditHostName(db, firstOf(object))
	case action == "карантин клона":
		head, rest := firstToken(object)
		name := auditHostName(db, head)
		object = strings.Join(nonempty(name, rest), " · ")
	case action == "бан снят на сервере":
		action = "снял бан аварийно"
		object = auditHostName(db, rawActor)
		actor = object
	case action == "подтвердил агента" || action == "отклонил агента" || action == "отозвал сертификат":
		head, rest := firstToken(object)
		if looksAuditID(head) {
			if rest != "" {
				object = rest
			} else {
				object = auditHostName(db, head)
			}
		}
	}
	if object == "" {
		if cleaned := stripJSON(rawDetail); cleaned != "" {
			object = cleaned
		}
	}
	if looksAuditID(object) {
		switch {
		case strings.Contains(action, "правил"):
			object = "удалённое правило"
		case strings.Contains(action, "групп"):
			object = "группа"
		case strings.Contains(action, "вопрос"):
			object = "вопрос"
		case strings.Contains(action, "тревог"):
			object = "тревога"
		default:
			object = ""
		}
	}
	return actor, action, object
}

func firstOf(object string) string {
	head, _ := firstToken(object)
	return head
}
