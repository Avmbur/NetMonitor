package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netmonitor/internal/policy"
)

func (s *Server) handlePolicyExport(w http.ResponseWriter, r *http.Request) {
	db := &checkedRead{db: s.st.DB}
	groups := s.listGroups(db)
	rules := s.listPolicyRules(db)
	if db.err != nil {
		http.Error(w, db.err.Error(), 500)
		return
	}
	names := exportHostNames(db)
	servers := exportParkNames(db)
	now := time.Now()
	txt := formatPolicyDump(now, servers, groups, rules, names)
	fname := "правила-" + now.Format("20060102-1504") + ".txt"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="pravila-`+now.Format("20060102-1504")+`.txt"; filename*=UTF-8''`+url.PathEscape(fname))
	_, _ = w.Write([]byte(txt))
}

func exportHostNames(db *checkedRead) map[string]string {
	out := map[string]string{}
	rows, err := db.Query(`SELECT host_id, COALESCE(NULLIF(hostname,''), host_id) FROM hosts`)
	if err != nil {
		return out
	}
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil && id != "" {
			out[id] = name
		}
	}
	rows.Close()
	ar, err := db.Query(`SELECT host_id, COALESCE(NULLIF(display_name,''),'') FROM agents WHERE trust_state IN ('pending','trusted','quarantined')`)
	if err != nil {
		return out
	}
	defer ar.Close()
	for ar.Next() {
		var id, name string
		if ar.Scan(&id, &name) == nil && id != "" && name != "" {
			out[id] = name
		}
	}
	return out
}

func exportParkNames(db *checkedRead) []string {
	var out []string
	rows, err := db.Query(`SELECT COALESCE(NULLIF(display_name,''), host_id) FROM agents WHERE trust_state IN ('pending','trusted','quarantined') ORDER BY first_seen_ms`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil && n != "" {
			out = append(out, n)
		}
	}
	return out
}

func formatPolicyDump(when time.Time, servers []string, groups []uiGroup, rules []policy.Rule, names map[string]string) string {
	var b strings.Builder
	b.WriteString("NetMonitor · правила и группы\n")
	b.WriteString("выгрузка " + when.Format("02.01.2006 15:04") + "\n")
	b.WriteString("серверы: ")
	if len(servers) == 0 {
		b.WriteString("нет")
	} else {
		b.WriteString(strings.Join(servers, ", "))
	}
	b.WriteString("\n\n======== группы ========\n")
	if len(groups) == 0 {
		b.WriteString("\nнет\n")
	}
	for _, g := range groups {
		b.WriteString("\n--- " + g.Name + " ---\n")
		b.WriteString("политика: " + groupPolicyRu(g.Policy) + "\n")
		b.WriteString("серверы: " + hostsJSONLabel(g.Hosts, names) + "\n")
		if len(g.Except) > 0 {
			b.WriteString("кроме: " + joinHostNames(g.Except, names) + "\n")
		}
		b.WriteString("адреса:\n")
		mem := strings.Split(strings.ReplaceAll(g.Members, "\r\n", "\n"), "\n")
		empty := true
		for _, line := range mem {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			empty = false
			b.WriteString(line + "\n")
		}
		if empty {
			b.WriteString("нет\n")
		}
	}
	b.WriteString("\n======== правила ========\n")
	if len(rules) == 0 {
		b.WriteString("\nнет\n")
	}
	for _, r := range rules {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = "без имени"
		}
		b.WriteString("\n--- " + name + " ---\n")
		if !r.Enabled {
			b.WriteString("включено: нет\n")
		}
		b.WriteString("действие: " + actionRu(r.Action) + "\n")
		b.WriteString("направление: " + dirRu(r.Match.Direction) + "\n")
		b.WriteString("протокол: " + protoRu(r.Match.Protocol) + "\n")
		if r.Match.AnyPort > 0 {
			b.WriteString(fmt.Sprintf("порт: %d\n", r.Match.AnyPort))
		} else {
			if r.Match.LocalPort > 0 {
				b.WriteString(fmt.Sprintf("локальный порт: %d\n", r.Match.LocalPort))
			}
			if r.Match.RemotePort > 0 {
				b.WriteString(fmt.Sprintf("удалённый порт: %d\n", r.Match.RemotePort))
			}
		}
		if r.GroupID != "" {
			gn := r.GroupID
			for _, g := range groups {
				if g.ID == r.GroupID {
					gn = g.Name
					break
				}
			}
			b.WriteString("группа: " + gn + "\n")
		}
		if p := strings.TrimSpace(r.Match.Process); p != "" {
			b.WriteString("процесс: " + p + "\n")
		}
		if len(r.Match.Bindings) > 0 {
			b.WriteString("привязки:\n")
			for _, bd := range r.Match.Bindings {
				b.WriteString(bindingLine(bd, names) + "\n")
			}
		}
		nets := append([]string{}, r.Match.Networks...)
		nets = append(nets, r.Match.Names...)
		nets = append(nets, r.Match.OnDemand...)
		if len(nets) > 0 {
			b.WriteString("адреса:\n")
			for _, n := range nets {
				n = strings.TrimSpace(n)
				if n != "" {
					b.WriteString(n + "\n")
				}
			}
		}
		b.WriteString("серверы: " + hostsSliceLabel(r.Hosts, names) + "\n")
		if len(r.Except) > 0 {
			b.WriteString("кроме: " + joinHostNames(r.Except, names) + "\n")
		}
		b.WriteString("срок: " + ruleUntilRu(r, when) + "\n")
	}
	if !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	return b.String()
}

func groupPolicyRu(p string) string {
	switch p {
	case "allow":
		return "разрешить"
	case "watch", "observe":
		return "наблюдать"
	case "signal", "alert":
		return "сообщать"
	case "block":
		return "блокировать"
	default:
		return p
	}
}

func actionRu(a string) string {
	switch a {
	case "allow":
		return "разрешить"
	case "deny", "block":
		return "запретить"
	case "observe", "watch":
		return "наблюдать"
	case "alert", "signal":
		return "сообщать"
	default:
		return a
	}
}

func dirRu(d string) string {
	switch d {
	case "in":
		return "вход"
	case "out":
		return "исход"
	case "both", "any", "":
		return "любое"
	default:
		return d
	}
}

func protoRu(p string) string {
	if p == "" || p == "any" {
		return "любой"
	}
	return p
}

func ruleUntilRu(r policy.Rule, now time.Time) string {
	if r.Once {
		return "один раз"
	}
	if r.UntilMS > 0 {
		return "до " + time.UnixMilli(r.UntilMS).In(now.Location()).Format("02.01.2006 15:04")
	}
	return "навсегда"
}

func hostsJSONLabel(raw []byte, names map[string]string) string {
	hs, err := parseScope(raw, "")
	if err != nil || hs == nil {
		return "все"
	}
	return joinHostNames(hs, names)
}

func hostsSliceLabel(hs []string, names map[string]string) string {
	if hs == nil {
		return "все"
	}
	return joinHostNames(hs, names)
}

func joinHostNames(ids []string, names map[string]string) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := names[id]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	return strings.Join(out, ", ")
}

func bindingLine(b policy.Binding, names map[string]string) string {
	host := b.Host
	if n := names[b.Host]; n != "" {
		host = n
	}
	var parts []string
	if host != "" {
		parts = append(parts, host)
	}
	if b.Cgroup != "" {
		parts = append(parts, b.Cgroup)
	}
	if b.Path != "" {
		parts = append(parts, b.Path)
	}
	if b.UID != nil {
		parts = append(parts, fmt.Sprintf("uid=%d", *b.UID))
	}
	if b.Name != "" && b.Path == "" {
		parts = append(parts, b.Name)
	}
	return strings.Join(parts, " · ")
}
