package server

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/policy"
	"netmonitor/internal/store"
)

type uiReportMeta struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Sub   string   `json:"sub"`
	Cols  []string `json:"cols"`
}

type uiReport struct {
	uiReportMeta
	Rows [][]string `json:"rows"`
}

func reportCatalog() []uiReportMeta {
	return []uiReportMeta{
		{ID: "maxaddr", Title: "Максимум с адреса (интернет)", Sub: "внешний IP, сколько накачал на парк за окно и за сутки", Cols: []string{"адрес", "главный сервер", "куда стучался", "пик за 3 с", "сумма 24 ч", "соединений"}},
		{ID: "topout", Title: "Топ исходящих назначений", Sub: "куда парк сам ходит в интернет, по объёму", Cols: []string{"назначение", "сервер", "процесс", "сумма 24 ч", "соединений", "правило"}},
		{ID: "new24", Title: "Новые адреса за 24 ч", Sub: "первый контакт, не из группы и не из стартового набора", Cols: []string{"адрес", "сервер", "направление", "порт", "процесс", "первый раз"}},
		{ID: "scanners", Title: "Сканеры портов", Sub: "один IP на несколько локальных портов за окно", Cols: []string{"адрес", "сервер", "портов за 1 мин", "какие", "статус"}},
		{ID: "sshfail", Title: "Неудачные SSH", Sub: "неудачный вход по SSH, порог 5 за 10 мин", Cols: []string{"адрес", "сервер", "неудач / 10 мин", "последняя", "статус"}},
		{ID: "blocked", Title: "Заблокированные сейчас", Sub: "живые баны и отрезанные обучением", Cols: []string{"цель", "причина", "сервер", "TTL", "настойчивый"}},
		{ID: "persist", Title: "Настойчивые баны", Sub: "TTL истёк, адрес сразу стучится снова", Cols: []string{"адрес", "ступень", "срабатываний", "сервер", "следующий TTL"}},
		{ID: "rulehits", Title: "Срабатывания правил за сутки", Sub: "сколько раз правило совпало", Cols: []string{"правило", "сервер", "совпадений", "последнее", "тип"}},
		{ID: "noreply", Title: "Без ответа", Sub: "исходящий ушёл, ответа не было", Cols: []string{"сервер", "процесс", "назначение", "попыток", "последний"}},
		{ID: "byvm", Title: "Объём по серверам за сутки", Sub: "вход / исход, internet отдельно от lan и своих", Cols: []string{"сервер", "вход интернет", "исход интернет", "lan / свои", "overlay"}},
		{ID: "groups", Title: "Группы: объём и контакты", Sub: "сколько ушло в известные наборы адресов", Cols: []string{"группа", "политика", "контактов 24 ч", "объём", "сервер"}},
		{ID: "gaps", Title: "Провалы сбора", Sub: "агент молчал или батч не доехал", Cols: []string{"сервер", "с", "по", "минут", "причина"}},
		{ID: "topproc", Title: "Топ процессов по объёму", Sub: "какой процесс сколько прокачал за окно", Cols: []string{"процесс", "сервер", "объём", "соединений"}},
		{ID: "newdns", Title: "Новые DNS-имена", Sub: "имя впервые увидели в окне", Cols: []string{"имя", "адрес", "сервер", "первый раз"}},
		{ID: "drops", Title: "DROP: кто режется", Sub: "срез по NFLOG, адрес и причина", Cols: []string{"адрес", "сервер", "причина", "срабатываний"}},
		{ID: "rulenone", Title: "Правила без срабатываний", Sub: "включённые правила, ни одного совпадения за окно", Cols: []string{"правило", "тип", "сервер"}},
		{ID: "longsess", Title: "Длинные открытые сессии", Sub: "живые соединения, самые старые сначала", Cols: []string{"сервер", "процесс", "направление", "адрес", "длится", "с"}},
		{ID: "lanin", Title: "Вход с LAN", Sub: "кто из локальной сети ходит на серверы парка", Cols: []string{"адрес", "сервер", "порт", "соединений", "объём"}},
		{ID: "montraf", Title: "Трафик к монитору", Sub: "обмен с адресом и портом nmserver", Cols: []string{"сервер", "направление", "адрес", "порт", "объём", "соединений"}},
	}
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	release, ok := uiReadSlot(r)
	if !ok {
		return
	}
	defer release()
	id := r.URL.Query().Get("id")
	if id == "" {
		id = "maxaddr"
	}
	from := parseMS(r.URL.Query().Get("from_ms"))
	to := parseMS(r.URL.Query().Get("to_ms"))
	if to == 0 {
		to = store.NowMS()
	}
	if from == 0 {
		from = to - 86400000
	}
	host := r.URL.Query().Get("server")
	rule := r.URL.Query().Get("rule_id")
	rep, err := s.buildReport(id, from, to, host, rule)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if r.URL.Query().Get("export") == "1" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Comma = ';'
		_ = cw.Write(rep.Cols)
		for _, row := range rep.Rows {
			_ = cw.Write(row)
		}
		cw.Flush()
		return
	}
	writeJSON(w, rep)
}

func (s *Server) buildReport(id string, from, to int64, host, ruleID string) (uiReport, error) {
	meta := uiReportMeta{}
	for _, m := range reportCatalog() {
		if m.ID == id {
			meta = m
			break
		}
	}
	if meta.ID == "" {
		return uiReport{}, fmt.Errorf("нет такого отчёта")
	}
	rep := uiReport{uiReportMeta: meta}
	var err error
	switch id {
	case "maxaddr":
		rep.Rows, err = s.repMaxAddr(from, to, host)
	case "topout":
		rep.Rows, err = s.repTopOut(from, to, host)
	case "new24":
		rep.Rows, err = s.repNew24(from, to, host)
	case "scanners":
		rep.Rows, err = s.repScanners(host)
	case "sshfail":
		rep.Rows, err = s.repSSH(from, to, host)
	case "blocked":
		rep.Rows, err = s.repBlocked(host)
	case "persist":
		rep.Rows, err = s.repPersist(host)
	case "rulehits":
		rep.Rows, err = s.repRuleHits(from, to, host, ruleID)
	case "noreply":
		rep.Rows, err = s.repNoReply(from, to, host)
	case "byvm":
		rep.Rows, err = s.repByVM(from, to, host)
	case "groups":
		rep.Rows, err = s.repGroups(from, to, host)
	case "gaps":
		rep.Rows, err = s.repGaps(host)
	case "topproc":
		rep.Rows, err = s.repTopProc(from, to, host)
	case "newdns":
		rep.Rows, err = s.repNewDNS(from, to, host)
	case "drops":
		rep.Rows, err = s.repDrops(from, to, host)
	case "rulenone":
		rep.Rows, err = s.repRuleNone(from, to, host)
	case "longsess":
		rep.Rows, err = s.repLongSess(host)
	case "lanin":
		rep.Rows, err = s.repLanIn(from, to, host)
	case "montraf":
		rep.Rows, err = s.repMonTraf(from, to, host)
	}
	if rep.Rows == nil {
		rep.Rows = [][]string{}
	}
	return rep, err
}

func hostClause(host, col string) (string, []any) {
	if host == "" || host == "all" {
		return "", nil
	}
	return " AND " + col + "=?", []any{host}
}

func (s *Server) repMaxAddr(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT f.remote_ip, COALESCE(h.hostname,f.host_id),
		SUM(CASE WHEN f.direction='in' THEN s.bytes_in ELSE 0 END),
		SUM(CASE WHEN f.direction='out' THEN s.bytes_in ELSE 0 END),
		MAX(COALESCE(f.local_port,0)), MAX(COALESCE(f.remote_port,0)),
		MAX(s.bytes_in), SUM(s.bytes_in), COUNT(DISTINCT f.flow_uid)
		FROM flow_samples s JOIN flows f ON f.flow_uid=s.flow_uid
		LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.remote_scope='internet' AND s.t0_ms>=? AND s.t0_ms<=?` + extra + `
		GROUP BY f.remote_ip ORDER BY SUM(s.bytes_in) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	rows, err := scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, srv string
		var inB, outB, lport, rport, peak, sum, n int64
		if err := rows.Scan(&ip, &srv, &inB, &outB, &lport, &rport, &peak, &sum, &n); err != nil {
			return nil, err
		}
		return []string{ip, srv, maxAddrDest(inB, outB, lport, rport), bytesHuman(peak), bytesHuman(sum), strconv.FormatInt(n, 10)}, nil
	})
	if err != nil || len(rows) > 0 {
		return rows, err
	}
	q = `SELECT f.remote_ip, COALESCE(h.hostname,f.host_id),
		SUM(CASE WHEN f.direction='in' THEN COALESCE(f.orig_bytes,0) ELSE 0 END),
		SUM(CASE WHEN f.direction='out' THEN COALESCE(f.reply_bytes,0) ELSE 0 END),
		MAX(COALESCE(f.local_port,0)), MAX(COALESCE(f.remote_port,0)),
		COUNT(*)
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.remote_scope='internet' AND f.last_seen_at_ms>=? AND f.last_seen_at_ms<=?` + extra + `
		GROUP BY f.remote_ip ORDER BY (SUM(CASE WHEN f.direction='in' THEN COALESCE(f.orig_bytes,0) ELSE 0 END)+SUM(CASE WHEN f.direction='out' THEN COALESCE(f.reply_bytes,0) ELSE 0 END)) DESC LIMIT 50`
	a = append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, srv string
		var inB, outB, lport, rport, n int64
		if err := rows.Scan(&ip, &srv, &inB, &outB, &lport, &rport, &n); err != nil {
			return nil, err
		}
		sum := inB + outB
		if sum == 0 && n == 0 {
			return nil, nil
		}
		return []string{ip, srv, maxAddrDest(inB, outB, lport, rport), bytesHuman(sum), bytesHuman(sum), strconv.FormatInt(n, 10)}, nil
	})
}

func maxAddrDest(inB, outB, lport, rport int64) string {
	if inB >= outB {
		if lport > 0 {
			return fmt.Sprintf("вход :%d", lport)
		}
		return "вход"
	}
	if rport > 0 {
		return fmt.Sprintf("исход :%d", rport)
	}
	return "исход"
}

func (s *Server) repTopOut(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT f.remote_ip||':'||COALESCE(f.remote_port,0), COALESCE(h.hostname,f.host_id), COALESCE(f.proc_comm,'—'),
		SUM(s.bytes_out), COUNT(DISTINCT f.flow_uid)
		FROM flow_samples s JOIN flows f ON f.flow_uid=s.flow_uid
		LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.direction='out' AND f.remote_scope='internet' AND s.t0_ms>=? AND s.t1_ms<=?` + extra + `
		GROUP BY f.remote_ip, f.remote_port, f.host_id ORDER BY SUM(s.bytes_out) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var dest, srv, proc string
		var sum, n int64
		if err := rows.Scan(&dest, &srv, &proc, &sum, &n); err != nil {
			return nil, err
		}
		return []string{dest, srv, proc, bytesHuman(sum), strconv.FormatInt(n, 10), "—"}, nil
	})
}

func (s *Server) repNew24(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT f.remote_ip, COALESCE(h.hostname,f.host_id), f.direction, COALESCE(f.remote_port,0), COALESCE(f.proc_comm,'—'), MIN(f.first_seen_at_ms)
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.first_seen_at_ms>=? AND f.first_seen_at_ms<=?` + extra + `
		GROUP BY f.remote_ip, f.host_id ORDER BY MIN(f.first_seen_at_ms) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, srv, dir, proc string
		var port, first int64
		if err := rows.Scan(&ip, &srv, &dir, &port, &proc, &first); err != nil {
			return nil, err
		}
		d := "исход"
		if dir == "in" {
			d = "вход"
		}
		return []string{ip, srv, d, strconv.FormatInt(port, 10), proc, fmtMS(first)}, nil
	})
}

func (s *Server) repScanners(host string) ([][]string, error) {
	extra, args := hostClause(host, "b.host_id")
	// The ports come from the minute before the ban: that window is what the
	// detector counted, and the report exists to show exactly it.
	q := `SELECT b.remote_ip, COALESCE(h.hostname, b.host_id, ''), b.state, b.created_at_ms,
		(SELECT COUNT(DISTINCT f.local_port) FROM firewall_events f
		   WHERE f.remote_ip=b.remote_ip AND f.direction='in' AND f.local_port IS NOT NULL
		     AND f.observed_at_ms BETWEEN b.created_at_ms-60000 AND b.created_at_ms
		     AND (b.host_id IS NULL OR f.host_id=b.host_id)),
		(SELECT GROUP_CONCAT(p, ', ') FROM (SELECT DISTINCT f.local_port AS p FROM firewall_events f
		   WHERE f.remote_ip=b.remote_ip AND f.direction='in' AND f.local_port IS NOT NULL
		     AND f.observed_at_ms BETWEEN b.created_at_ms-60000 AND b.created_at_ms
		     AND (b.host_id IS NULL OR f.host_id=b.host_id) ORDER BY p LIMIT 12))
		FROM blocks b LEFT JOIN hosts h ON h.host_id=b.host_id WHERE b.source='scan'` + extra + ` ORDER BY b.created_at_ms DESC LIMIT 50`
	return scanReport(s.st.DB, q, args, func(rows *sql.Rows) ([]string, error) {
		var ip, name, state string
		var created int64
		var ports sql.NullInt64
		var list sql.NullString
		if err := rows.Scan(&ip, &name, &state, &created, &ports, &list); err != nil {
			return nil, err
		}
		if name == "" {
			name = "весь парк"
		}
		n, which := "—", "—"
		if ports.Valid && ports.Int64 > 0 {
			n = strconv.FormatInt(ports.Int64, 10)
		}
		if list.Valid && list.String != "" {
			which = list.String
		}
		return []string{ip, name, n, which, banState(state)}, nil
	})
}

func (s *Server) repSSH(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT f.remote_ip, COALESCE(h.hostname, f.host_id), COUNT(*), MAX(f.observed_at_ms)
		FROM ssh_failures f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.observed_at_ms>=? AND f.observed_at_ms<=?` + extra + `
		GROUP BY f.remote_ip, f.host_id ORDER BY COUNT(*) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, name string
		var n, last int64
		if err := rows.Scan(&ip, &name, &n, &last); err != nil {
			return nil, err
		}
		st := "наблюдаем"
		if n >= 5 {
			st = "порог"
		}
		return []string{ip, name, strconv.FormatInt(n, 10), fmtMS(last), st}, nil
	})
}

func (s *Server) repBlocked(host string) ([][]string, error) {
	bans, err := readBans(s.st.DB, "WHERE state='active' ORDER BY created_at_ms DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, b := range bans {
		if host != "" && host != "all" && !b.covers(host) {
			continue
		}
		ttl := "навсегда"
		if b.ExpiresAt > 0 {
			ttl = time.UnixMilli(b.ExpiresAt).Local().Format("15:04")
		}
		pers := "нет"
		if b.Escalate > 0 {
			pers = "да"
		}
		scope := "все"
		if len(b.Hosts) == 1 {
			scope = b.Hosts[0]
		}
		rows = append(rows, []string{b.RemoteIP, b.Reason, scope, ttl, pers})
	}
	return rows, nil
}

func (s *Server) repPersist(host string) ([][]string, error) {
	extra, args := hostClause(host, "host_id")
	q := `SELECT remote_ip, MAX(escalate_step), COUNT(*), COALESCE(host_id,'все') FROM blocks WHERE escalate_step>0` + extra + ` GROUP BY remote_ip ORDER BY MAX(escalate_step) DESC`
	return scanReport(s.st.DB, q, args, func(rows *sql.Rows) ([]string, error) {
		var ip, hid string
		var step, n int
		if err := rows.Scan(&ip, &step, &n, &hid); err != nil {
			return nil, err
		}
		next := "1 ч"
		if step >= 1 {
			next = "6 ч"
		}
		if step >= 2 {
			next = "24 ч"
		}
		if step >= 3 {
			next = "7 суток"
		}
		return []string{ip, strconv.Itoa(step), strconv.Itoa(n), hid, next}, nil
	})
}

func (s *Server) repRuleHits(from, to int64, host, ruleID string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT f.host_id, COALESCE(h.hostname,f.host_id), f.direction, f.protocol, COALESCE(f.remote_ip,''),
		COALESCE(f.local_port,0), COALESCE(f.remote_port,0), COALESCE(f.proc_path,''), COALESCE(f.proc_comm,''), f.proc_uid, COALESCE(f.proc_cgroup,''), f.last_seen_at_ms
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.last_seen_at_ms>=? AND f.last_seen_at_ms<=?` + extra
	a := append([]any{from, to}, args...)
	rows, err := s.st.DB.Query(q, a...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	park := "learn"
	_ = s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='park_mode'`).Scan(&park)
	never := neverPrefixes(s.st.DB)
	decided := map[string]hostDecision{}
	now := store.NowMS()
	type acc struct {
		n, last int64
		kind    string
	}
	hit := map[string]*acc{}
	for rows.Next() {
		var hid, srv, dir, proto, rip, path, comm, cg string
		var lp, rp int
		var uid sql.NullInt64
		var last int64
		if err := rows.Scan(&hid, &srv, &dir, &proto, &rip, &lp, &rp, &path, &comm, &uid, &cg, &last); err != nil {
			return nil, err
		}
		d, ok := decided[hid]
		if !ok {
			hd, e := loadHostDecision(s.st.DB, hid, never, park)
			if e != nil {
				return nil, e
			}
			decided[hid] = hd
			d = hd
		}
		var puid *int
		if uid.Valid {
			n := int(uid.Int64)
			puid = &n
		}
		c := policy.Contact{Host: hid, Direction: dir, Protocol: proto, RemoteIP: rip, LocalPort: lp, RemotePort: rp, Process: path, Cgroup: cg, UID: puid}
		name, action, _ := d.resolve(c, now)
		if name == "" || name == "—" {
			continue
		}
		if ruleID != "" && name != ruleID {
			continue
		}
		key := name + "\x00" + srv
		x := hit[key]
		if x == nil {
			x = &acc{kind: action}
			hit[key] = x
		}
		x.n++
		if last > x.last {
			x.last = last
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type row struct {
		name, srv, kind string
		n, last         int64
	}
	list := make([]row, 0, len(hit))
	for k, x := range hit {
		name, srv, _ := strings.Cut(k, "\x00")
		list = append(list, row{name, srv, x.kind, x.n, x.last})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].name < list[j].name
	})
	if len(list) > 50 {
		list = list[:50]
	}
	out := make([][]string, 0, len(list))
	for _, r := range list {
		out = append(out, []string{r.name, r.srv, strconv.FormatInt(r.n, 10), fmtMS(r.last), ruleHitKind(r.kind)})
	}
	return out, nil
}

func ruleHitKind(action string) string {
	switch action {
	case "allow":
		return "разрешить"
	case "deny":
		return "запретить"
	case "learn":
		return "обучение"
	case "alert":
		return "сообщать"
	default:
		if action == "" {
			return "правило"
		}
		return action
	}
}

func (s *Server) repNoReply(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT COALESCE(h.hostname,f.host_id), COALESCE(f.proc_comm,'—'), f.remote_ip||':'||COALESCE(f.remote_port,0), COUNT(*), MAX(f.last_seen_at_ms)
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.direction='out' AND f.reply_seen=0 AND f.last_seen_at_ms>=? AND f.last_seen_at_ms<=?` + extra + `
		GROUP BY f.host_id, f.remote_ip, f.remote_port ORDER BY MAX(f.last_seen_at_ms) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var srv, proc, dest string
		var n, last int64
		if err := rows.Scan(&srv, &proc, &dest, &n, &last); err != nil {
			return nil, err
		}
		return []string{srv, proc, dest, strconv.FormatInt(n, 10), fmtMS(last)}, nil
	})
}

func (s *Server) repByVM(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "t.host_id")
	q := `SELECT COALESCE(h.hostname,t.host_id),
		SUM(CASE WHEN t.direction='in' AND t.remote_scope='internet' THEN t.bytes_in ELSE 0 END),
		SUM(CASE WHEN t.direction='out' AND t.remote_scope='internet' THEN t.bytes_out ELSE 0 END),
		SUM(CASE WHEN t.remote_scope IN ('lan','own') THEN t.bytes_in+t.bytes_out ELSE 0 END),
		SUM(CASE WHEN t.remote_scope='overlay' THEN t.bytes_in+t.bytes_out ELSE 0 END)
		FROM traffic_1m t LEFT JOIN hosts h ON h.host_id=t.host_id
		WHERE t.bucket_start_ms>=? AND t.bucket_start_ms<=?` + extra + `
		GROUP BY t.host_id`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var srv string
		var inI, outI, lan, ov int64
		if err := rows.Scan(&srv, &inI, &outI, &lan, &ov); err != nil {
			return nil, err
		}
		return []string{srv, bytesHuman(inI), bytesHuman(outI), bytesHuman(lan), bytesHuman(ov)}, nil
	})
}

func (s *Server) repGroups(from, to int64, host string) ([][]string, error) {
	_ = from
	_ = to
	_ = host
	rows, err := s.st.DB.Query(`SELECT name, policy, (SELECT COUNT(*) FROM ip_group_members m WHERE m.group_id=g.group_id) FROM ip_groups g ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		var name, pol string
		var n int
		if rows.Scan(&name, &pol, &n) != nil {
			continue
		}
		out = append(out, []string{name, uiPolicy(pol), strconv.Itoa(n), "—", "все"})
	}
	return out, nil
}

func (s *Server) repGaps(host string) ([][]string, error) {
	extra, args := hostClause(host, "h.host_id")
	q := `SELECT COALESCE(h.hostname,h.host_id), COALESCE(h.last_seen_ms,0) FROM hosts h JOIN agents a ON a.host_id=h.host_id WHERE a.trust_state='trusted'` + extra
	now := store.NowMS()
	return scanReport(s.st.DB, q, args, func(rows *sql.Rows) ([]string, error) {
		var srv string
		var last int64
		if err := rows.Scan(&srv, &last); err != nil {
			return nil, err
		}
		if last == 0 || now-last < 60000 {
			return nil, nil
		}
		mins := (now - last) / 60000
		return []string{srv, fmtMS(last), "сейчас", strconv.FormatInt(mins, 10), "нет данных"}, nil
	})
}

func (s *Server) repTopProc(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT COALESCE(f.proc_comm,''), COALESCE(f.proc_path,''), COALESCE(h.hostname,f.host_id),
		SUM(s.bytes_in+s.bytes_out), COUNT(DISTINCT f.flow_uid)
		FROM flow_samples s JOIN flows f ON f.flow_uid=s.flow_uid
		LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE s.t0_ms>=? AND s.t0_ms<=?` + extra + `
		GROUP BY f.proc_comm, f.host_id ORDER BY SUM(s.bytes_in+s.bytes_out) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var comm, path, srv string
		var sum, n int64
		if err := rows.Scan(&comm, &path, &srv, &sum, &n); err != nil {
			return nil, err
		}
		name := displayProc(comm, path)
		if name == "" {
			name = "—"
		}
		return []string{name, srv, bytesHuman(sum), strconv.FormatInt(n, 10)}, nil
	})
}

func (s *Server) repNewDNS(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "d.host_id")
	q := `SELECT d.name, d.ip, COALESCE(h.hostname,d.host_id), MIN(d.first_seen_ms)
		FROM dns_seen d LEFT JOIN hosts h ON h.host_id=d.host_id
		WHERE d.first_seen_ms>=? AND d.first_seen_ms<=?` + extra + `
		GROUP BY d.name, d.ip ORDER BY MIN(d.first_seen_ms) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var name, ip, srv string
		var first int64
		if err := rows.Scan(&name, &ip, &srv, &first); err != nil {
			return nil, err
		}
		return []string{name, ip, srv, fmtMS(first)}, nil
	})
}

func (s *Server) repDrops(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "e.host_id")
	q := `SELECT COALESCE(e.remote_ip,'—'), COALESCE(h.hostname,e.host_id),
		COALESCE(NULLIF(e.rule_tag,''), e.verdict, 'drop'), SUM(e.hits)
		FROM firewall_events e LEFT JOIN hosts h ON h.host_id=e.host_id
		WHERE e.observed_at_ms>=? AND e.observed_at_ms<=?` + extra + `
		GROUP BY e.remote_ip, e.host_id, COALESCE(NULLIF(e.rule_tag,''), e.verdict, 'drop')
		ORDER BY SUM(e.hits) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, srv, why string
		var n int64
		if err := rows.Scan(&ip, &srv, &why, &n); err != nil {
			return nil, err
		}
		return []string{ip, srv, why, strconv.FormatInt(n, 10)}, nil
	})
}

func (s *Server) repRuleNone(from, to int64, host string) ([][]string, error) {
	hits, err := s.repRuleHits(from, to, host, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range hits {
		if len(r) > 0 {
			seen[r[0]] = true
		}
	}
	rs, err := readPolicyRules(s.st.DB)
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, r := range rs {
		if !r.Enabled || strings.TrimSpace(r.Name) == "" || seen[r.Name] {
			continue
		}
		scope := "все"
		if len(r.Hosts) == 1 {
			scope = r.Hosts[0]
		} else if len(r.Hosts) > 1 {
			scope = strconv.Itoa(len(r.Hosts)) + " серверов"
		}
		out = append(out, []string{r.Name, ruleHitKind(r.Action), scope})
	}
	return out, nil
}

func (s *Server) repLongSess(host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	now := store.NowMS()
	q := `SELECT COALESCE(h.hostname,f.host_id), COALESCE(f.proc_comm,''), COALESCE(f.proc_path,''), f.direction,
		COALESCE(f.remote_ip,''), COALESCE(f.remote_port,0), COALESCE(f.first_seen_at_ms, f.last_seen_at_ms), f.last_seen_at_ms
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.ended_at_ms IS NULL` + extra + `
		ORDER BY COALESCE(f.first_seen_at_ms, f.last_seen_at_ms) ASC LIMIT 50`
	return scanReport(s.st.DB, q, args, func(rows *sql.Rows) ([]string, error) {
		var srv, comm, path, dir, ip string
		var port, first, last int64
		if err := rows.Scan(&srv, &comm, &path, &dir, &ip, &port, &first, &last); err != nil {
			return nil, err
		}
		name := displayProc(comm, path)
		if name == "" {
			name = "—"
		}
		d := "исход"
		if dir == "in" {
			d = "вход"
		}
		addr := ip
		if port > 0 {
			addr += ":" + strconv.FormatInt(port, 10)
		}
		start := first
		if start <= 0 {
			start = last
		}
		return []string{srv, name, d, addr, durHuman(now - start), fmtMS(start)}, nil
	})
}

func (s *Server) repLanIn(from, to int64, host string) ([][]string, error) {
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT COALESCE(f.remote_ip,''), COALESCE(h.hostname,f.host_id), COALESCE(f.local_port,0), COUNT(*), SUM(COALESCE(f.orig_bytes,0))
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.direction='in' AND f.remote_scope='lan' AND f.last_seen_at_ms>=? AND f.last_seen_at_ms<=?` + extra + `
		GROUP BY f.remote_ip, f.host_id, f.local_port ORDER BY COUNT(*) DESC LIMIT 50`
	a := append([]any{from, to}, args...)
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var ip, srv string
		var port, n, sum int64
		if err := rows.Scan(&ip, &srv, &port, &n, &sum); err != nil {
			return nil, err
		}
		p := "—"
		if port > 0 {
			p = strconv.FormatInt(port, 10)
		}
		return []string{ip, srv, p, strconv.FormatInt(n, 10), bytesHuman(sum)}, nil
	})
}

func (s *Server) repMonTraf(from, to int64, host string) ([][]string, error) {
	mon := ""
	_ = s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='listen_host'`).Scan(&mon)
	portS := "8443"
	_ = s.st.DB.QueryRow(`SELECT v FROM settings WHERE k='listen_port'`).Scan(&portS)
	port, _ := strconv.Atoi(portS)
	if port <= 0 {
		port = 8443
	}
	extra, args := hostClause(host, "f.host_id")
	q := `SELECT COALESCE(h.hostname,f.host_id), f.direction, COALESCE(f.remote_ip,''), COALESCE(f.remote_port,0), COALESCE(f.local_port,0),
		SUM(COALESCE(f.orig_bytes,0)+COALESCE(f.reply_bytes,0)), COUNT(*)
		FROM flows f LEFT JOIN hosts h ON h.host_id=f.host_id
		WHERE f.last_seen_at_ms>=? AND f.last_seen_at_ms<=?` + extra
	a := append([]any{from, to}, args...)
	if mon != "" && mon != "0.0.0.0" && mon != "::" {
		q += ` AND (f.remote_ip=? OR f.local_ip=? OR f.remote_port=? OR f.local_port=?)`
		a = append(a, mon, mon, port, port)
	} else {
		q += ` AND (f.remote_port=? OR f.local_port=?)`
		a = append(a, port, port)
	}
	q += ` GROUP BY f.host_id, f.direction, f.remote_ip, f.remote_port ORDER BY SUM(COALESCE(f.orig_bytes,0)+COALESCE(f.reply_bytes,0)) DESC LIMIT 50`
	return scanReport(s.st.DB, q, a, func(rows *sql.Rows) ([]string, error) {
		var srv, dir, ip string
		var rp, lp, sum, n int64
		if err := rows.Scan(&srv, &dir, &ip, &rp, &lp, &sum, &n); err != nil {
			return nil, err
		}
		d := "исход"
		if dir == "in" {
			d = "вход"
		}
		p := rp
		if dir == "in" {
			p = lp
		}
		ps := "—"
		if p > 0 {
			ps = strconv.FormatInt(p, 10)
		}
		return []string{srv, d, ip, ps, bytesHuman(sum), strconv.FormatInt(n, 10)}, nil
	})
}

func durHuman(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	sec := ms / 1000
	if sec < 60 {
		return strconv.FormatInt(sec, 10) + " с"
	}
	min := sec / 60
	if min < 60 {
		return strconv.FormatInt(min, 10) + " мин"
	}
	h := min / 60
	if h < 48 {
		return strconv.FormatInt(h, 10) + " ч"
	}
	return strconv.FormatInt(h/24, 10) + " сут"
}

func scanReport(db *sql.DB, q string, args []any, fn func(*sql.Rows) ([]string, error)) ([][]string, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		r, err := fn(rows)
		if err != nil {
			return nil, err
		}
		if r != nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func bytesHuman(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	if n < 1024*1024 {
		return strconv.FormatInt(n/1024, 10) + " KB"
	}
	return strconv.FormatInt(n/(1024*1024), 10) + " MB"
}

// One column, one language: the ban table keeps English states, the report
// shows what the operator sees elsewhere in the interface.
func banState(state string) string {
	switch state {
	case "active":
		return "бан"
	case "removed":
		return "снят"
	case "expired":
		return "срок вышел"
	case "rejected":
		return "отклонён"
	default:
		return state
	}
}
