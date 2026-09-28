package server_test

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"testing"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/server"
	"netmonitor/internal/store"
)

func TestRuleClosesQuestion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	if err := server.Init(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}, "x"); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	host := idgen.NewV7()
	qid := idgen.NewV7()
	ag := idgen.NewV7()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,1,1)`, host, "pg"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, first_seen_ms) VALUES(?,?,?,?,1)`,
			ag, host, "fp", "trusted"); err != nil {
			return err
		}
		_, err := tx.Exec(
			`INSERT INTO learn_questions(question_id, host_id, dedup_key, opened_at_ms, repeats, last_seen_ms, direction, protocol, remote_ip, remote_port, status)
			 VALUES(?,?,?,1,1,1,'out','tcp','1.1.1.1',443,'open')`, qid, host, "out|tcp|1.1.1.1|443")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	s, err := server.Listen(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.Serve() }()
	time.Sleep(80 * time.Millisecond)
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}},
		Jar:       jar,
		Timeout:   5 * time.Second,
	}
	base := "https://" + s.Addr()
	ok, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	body, _ := json.Marshal(map[string]any{
		"kind": "allow", "ip": "1.1.1.1", "proto": "tcp", "direction": "out", "port": 443,
		"question_id": qid, "together": true,
	})
	r, err := cl.Post(base+"/ui/api/rule", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("rule %d", r.StatusCode)
	}
	st, err = store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var status, answer string
	if err := st.DB.QueryRow(`SELECT status, COALESCE(answer,'') FROM learn_questions WHERE question_id=?`, qid).Scan(&status, &answer); err != nil {
		t.Fatal(err)
	}
	if status != "answered" || answer != "allow" {
		t.Fatalf("status=%s answer=%s", status, answer)
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM policy_rules WHERE payload LIKE '%1.1.1.1%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("allow %d", n)
	}
	st2, err := cl.Get(base + "/ui/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Body.Close()
	var ui struct {
		Questions []any `json:"questions"`
		Rules     []any `json:"rules"`
	}
	if err := json.NewDecoder(st2.Body).Decode(&ui); err != nil {
		t.Fatal(err)
	}
	if len(ui.Questions) != 0 {
		t.Fatalf("open questions %d", len(ui.Questions))
	}
	// Пять стартовых, решение по вопросу и служебное «обновления».
	if len(ui.Rules) != 7 {
		t.Fatalf("rules %d", len(ui.Rules))
	}
}

func TestDismissQuestion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	if err := server.Init(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: 8443}, "x"); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	host := idgen.NewV7()
	qid := idgen.NewV7()
	ag := idgen.NewV7()
	if err := st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO hosts(host_id, hostname, first_seen_ms, last_seen_ms) VALUES(?,?,1,1)`, host, "pg"); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO agents(agent_id, host_id, cert_fingerprint, trust_state, first_seen_ms) VALUES(?,?,?,?,1)`,
			ag, host, "fp", "trusted"); err != nil {
			return err
		}
		_, err := tx.Exec(
			`INSERT INTO learn_questions(question_id, host_id, dedup_key, opened_at_ms, repeats, last_seen_ms, direction, protocol, remote_ip, remote_port, status)
			 VALUES(?,?,?,1,1,1,'out','tcp','9.9.9.9',9,'open')`, qid, host, "out|tcp|9.9.9.9|9")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	s, err := server.Listen(server.Config{DataDir: dir, ListenHost: "127.0.0.1", ListenPort: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go func() { _ = s.Serve() }()
	time.Sleep(80 * time.Millisecond)
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}},
		Jar:       jar,
		Timeout:   5 * time.Second,
	}
	base := "https://" + s.Addr()
	ok, err := cl.Post(base+"/ui/login", "application/json", bytes.NewBufferString(`{"login":"adm","password":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	ok.Body.Close()
	r, err := cl.Post(base+"/ui/api/question", "application/json", bytes.NewBufferString(`{"id":"`+qid+`","op":"dismiss"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("dismiss %d %s", r.StatusCode, body)
	}
	st, err = store.OpenMonitor(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var status, answer string
	if err := st.DB.QueryRow(`SELECT status, COALESCE(answer,'') FROM learn_questions WHERE question_id=?`, qid).Scan(&status, &answer); err != nil {
		t.Fatal(err)
	}
	if status != "answered" || answer != "dismiss" {
		t.Fatalf("status=%s answer=%s", status, answer)
	}
}
