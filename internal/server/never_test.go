package server

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNeverCRUDAndPolicyRevision(t *testing.T) {
	s, _ := batchFixture(t)
	id, err := saveNever(s.st, "", "198.18.0.19/24", "test", "adm")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.NeverBlock) != 1 || pr.NeverBlock[0] != "198.18.0.0/24" || pr.PolicyRev != 1 {
		t.Fatal(pr)
	}
	if _, err := saveNever(s.st, "", "198.18.0.0/24", "duplicate", "adm"); !errors.Is(err, errNeverDuplicate) {
		t.Fatal(err)
	}
	if _, err := saveNever(s.st, id, "fd00:d10::1", "v6", "adm"); err != nil {
		t.Fatal(err)
	}
	pr, err = s.pollSnapshot("a", "trusted", 1)
	if err != nil || pr.PolicyRev != 2 || pr.NeverBlock[0] != "fd00:d10::1/128" {
		t.Fatal(pr, err)
	}
	if _, err := saveNever(s.st, "missing", "1.1.1.1", "", "adm"); !errors.Is(err, errNeverMissing) {
		t.Fatal(err)
	}
	if err := deleteNever(s.st, id); err != nil {
		t.Fatal(err)
	}
	pr, err = s.pollSnapshot("a", "trusted", 2)
	if err != nil || pr.PolicyRev != 3 || len(pr.NeverBlock) != 0 {
		t.Fatal(pr, err)
	}
	if err := deleteNever(s.st, id); !errors.Is(err, errNeverMissing) {
		t.Fatal(err)
	}
}
func TestNeverFailureRollsBackAndMonitorLocked(t *testing.T) {
	s, _ := batchFixture(t)
	if _, err := s.st.DB.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'full'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := saveNever(s.st, "", "198.18.0.2", "x", "adm"); err == nil {
		t.Fatal("SQL error hidden")
	}
	var n, rev int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM never_block").Scan(&n)
	s.st.DB.QueryRow("SELECT policy_rev FROM agents").Scan(&rev)
	if n != 0 || rev != 0 {
		t.Fatal("partial update", n, rev)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		r := httptest.NewRequest(method, "/ui/api/never-block/monitor", bytes.NewBufferString(`{"id":"monitor","addr":"1.1.1.1"}`))
		r.SetPathValue("id", "monitor")
		w := httptest.NewRecorder()
		s.handleNever(w, r)
		if w.Code != 403 {
			t.Fatal("monitor editable", w.Code)
		}
	}
}
func TestNeverInvalidInputNoMutation(t *testing.T) {
	s, _ := batchFixture(t)
	for _, addr := range []string{"", "wat", "1.2.3.4/99", "fe80::1%eth0", "::ffff:198.18.0.2/128"} {
		if _, err := saveNever(s.st, "", addr, "", "adm"); err == nil {
			t.Fatal("accepted", addr)
		}
	}
	if err := s.st.Update(func(tx *sql.Tx) error { _, err := tx.Exec("DROP TABLE never_block"); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := saveNever(s.st, "", "198.18.0.2", "", "adm"); err == nil {
		t.Fatal("missing table became success")
	}
}
