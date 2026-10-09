package server

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"

	"strconv"
	"strings"
	"time"

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
		{ID: "scanners", Title: "Сканеры портов", Sub: "один IP на несколько локальных портов за окно", Cols: []string{"адрес", "сервер", "портов за 1 мин", "какие", "статус"}},
		{ID: "sshfail", Title: "Неудачные SSH", Sub: "неудачный вход по SSH, порог 5 за 10 мин", Cols: []string{"адрес", "сервер", "неудач / 10 мин", "последняя", "статус"}},
		{ID: "blocked", Title: "Заблокированные сейчас", Sub: "живые баны и отрезанные обучением", Cols: []string{"цель", "причина", "сервер", "TTL", "настойчивый"}},
		{ID: "persist", Title: "Настойчивые баны", Sub: "TTL истёк, адрес сразу стучится снова", Cols: []string{"адрес", "ступень", "срабатываний", "сервер", "следующий TTL"}},
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
		id = "scanners"
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
	rep, err := s.buildReport(id, from, to, host)
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

func (s *Server) buildReport(id string, from, to int64, host string) (uiReport, error) {
	meta := uiReportMeta{}
	for _, m := range reportCatalog() {
		if m.ID == id {
			meta = m
			break
		}
	}
	if meta.ID == "" || meta.ID != "scanners" && meta.ID != "sshfail" && meta.ID != "blocked" && meta.ID != "persist" {
		return uiReport{}, fmt.Errorf("нет такого отчёта")
	}
	rep := uiReport{uiReportMeta: meta}
	var err error
	switch id {
	case "scanners":
		rep.Rows, err = s.repScanners(host)
	case "sshfail":
		rep.Rows, err = s.repSSH(from, to, host)
	case "blocked":
		rep.Rows, err = s.repBlocked(host)
	case "persist":
		rep.Rows, err = s.repPersist(host)
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

func (s *Server) repScanners(host string) ([][]string, error) {
	extra, args := hostClause(host, "b.host_id")
	// A new ban stores the ports that caused it. An older ban still reads the
	// minute of firewall events that the detector counted.
	q := `SELECT b.remote_ip,COALESCE(h.hostname,b.host_id,''),b.state,COALESCE(b.scan_ports,'')
 FROM blocks b LEFT JOIN hosts h ON h.host_id=b.host_id WHERE b.source='scan'` + extra + ` ORDER BY b.created_at_ms DESC LIMIT 50`
	return scanReport(s.st.DB, q, args, func(rows *sql.Rows) ([]string, error) {
		var ip, name, state, stored string
		if err := rows.Scan(&ip, &name, &state, &stored); err != nil {
			return nil, err
		}
		if name == "" {
			name = "весь парк"
		}
		n, which := "—", "—"
		if stored != "" {
			parts := splitScanPorts(stored)
			if len(parts) > 0 {
				n = strconv.Itoa(len(parts))
			}
			if len(parts) > 12 {
				parts = parts[:12]
			}
			if len(parts) > 0 {
				which = strings.Join(parts, ", ")
			}
		}
		return []string{ip, name, n, which, banState(state)}, nil
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

func (s *Server) hostLabel(id string) string {
	if s.st == nil {
		return id
	}
	var name string
	err := s.st.DB.QueryRow(`SELECT COALESCE(hostname, ?) FROM hosts WHERE host_id=?`, id, id).Scan(&name)
	if err != nil {
		return id
	}
	return name
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
