package server

import (
	"regexp"
	"strings"
)

var alertIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func lastIPv4(s string) string {
	found := alertIPv4.FindAllString(s, -1)
	if len(found) == 0 {
		return ""
	}
	return found[len(found)-1]
}

func withAlertIP(ip, msg string) string {
	if ip == "" {
		return msg
	}
	return ip + " — " + msg
}

func alertEventText(a uiAlert, host string) string {
	ip := a.Addr
	if ip == "" {
		ip = lastIPv4(a.Text)
	}
	switch a.Rule {
	case "scan-cap":
		return withAlertIP(ip, "слишком много сканов")
	case "ssh-cap":
		return withAlertIP(ip, "шквал по SSH")
	case "storm":
		t := strings.ToLower(a.Text)
		if strings.Contains(t, "ssh") {
			return "шторм SSH"
		}
		if strings.Contains(a.Text, "скан") {
			return "шторм сканов"
		}
		return "шторм"
	case "scan":
		return withAlertIP(ip, "скан портов")
	case "ssh":
		return withAlertIP(ip, "перебор SSH")
	case "persist":
		return withAlertIP(ip, "вернулся после бана на 7 суток")
	case "silent", "policy-fail":
		return a.Text
	case "paused_local":
		tail := "бан снят руками"
		if host != "" && host != "монитор" {
			tail += " на " + host
		}
		return withAlertIP(ip, tail)
	case "clone":
		head := host
		if head == "" || head == "монитор" {
			head = "сервер"
		}
		msg := head + " — чужая копия ключа"
		if ip != "" {
			msg += " с " + ip
		}
		return msg
	case "disk-90":
		return "диск 90% — мало места"
	case "disk-80":
		return "диск 80% — мало места"
	default:
		return a.Text
	}
}

func alertHint(rule string, hist bool) string {
	if hist {
		return "агент был офлайн, дослали очередь. живое не режет."
	}
	switch rule {
	case "scan-cap", "ssh-cap":
		return "старая тревога: потолка автобана нет, баны ставятся"
	case "storm":
		return "много атак за минуту. автобан идёт, внешние подключения закрыты. снимутся через 10 мин после атак."
	case "scan", "ssh":
		return "адрес забанен. закрой карточку — строка просмотрена, сирена молчит."
	case "persist":
		return "вернулся после 7 суток. лестница кончилась: бан навсегда или оставить."
	case "silent":
		return "нет связи больше 2 мин. трафик и новые баны не доходят."
	case "policy-fail":
		return "политика не применилась. на сервере прежние правила."
	case "paused_local":
		return "снят с консоли сервера. монитор не вернёт, пока бан не вернут."
	case "clone":
		return "тот же ключ агента с другого адреса"
	case "disk-90":
		return "на диске совсем мало места"
	case "disk-80":
		return "на диске мало места"
	default:
		return ""
	}
}

func hostTitle(q policyReader, hostID string) string {
	if hostID == "" || hostID == "monitor" {
		return "монитор"
	}
	var name string
	if q.QueryRow(`SELECT COALESCE(NULLIF(display_name,''),'') FROM agents WHERE host_id=? AND COALESCE(display_name,'')!='' LIMIT 1`, hostID).Scan(&name) == nil && strings.TrimSpace(name) != "" {
		return name
	}
	if q.QueryRow(`SELECT COALESCE(hostname,'') FROM hosts WHERE host_id=?`, hostID).Scan(&name) == nil && strings.TrimSpace(name) != "" {
		return name
	}
	return hostID
}

func hostNames(db policyReader) map[string]string {
	out := map[string]string{}
	rows, err := db.Query(`SELECT host_id, COALESCE(hostname,'') FROM hosts`)
	if err != nil {
		return out
	}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil && strings.TrimSpace(name) != "" {
			out[id] = strings.TrimSpace(name)
		}
	}
	rows.Close()
	rows, err = db.Query(`SELECT host_id, COALESCE(display_name,'') FROM agents WHERE COALESCE(display_name,'')!=''`)
	if err != nil {
		return out
	}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil && strings.TrimSpace(name) != "" {
			out[id] = strings.TrimSpace(name)
		}
	}
	rows.Close()
	return out
}

func namedHosts(db policyReader, hosts []string) []string {
	if hosts == nil {
		return nil
	}
	names := hostNames(db)
	out := make([]string, len(hosts))
	for i, id := range hosts {
		if name := names[id]; name != "" {
			out[i] = name
		} else {
			out[i] = id
		}
	}
	return out
}
