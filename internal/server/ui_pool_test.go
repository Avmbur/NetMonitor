package server

import (
	"database/sql"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"netmonitor/internal/store"
)

// Много одновременных опросов морды не должны вешать монитор: раньше
// четыре опроса, держащие курсор и ждущие второе соединение, забирали
// весь пул (4, одно из них навсегда у писателя) — вставали запись и агенты.
func TestUIStateParallelPollsDoNotStarvePool(t *testing.T) {
	s, _ := batchFixture(t)
	now := store.NowMS()
	if _, err := s.st.DB.Exec(`UPDATE agents SET trust_state='trusted' WHERE agent_id='a'`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"f1", "f2", "f3"} {
		if _, err := s.st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,remote_ip,remote_ip_bin,remote_scope,origin,received_at_ms)
			VALUES(?,'h','a','b',?,?,4,'tcp','1.1.1.1',zeroblob(16),'10.0.0.1',zeroblob(16),'out','10.0.0.1',zeroblob(16),'1.1.1.1',zeroblob(16),'internet','host',?)`, id, now, now, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"правило: delete", "группа: member", "снял вопрос", "вход"} {
		if _, err := s.st.DB.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,'adm',?,'x')`, a, now, a); err != nil {
			t.Fatal(err)
		}
	}
	urls := []string{"/ui/api/state?section=activity", "/ui/api/state?section=log", "/ui/api/state?section=log&action=rule", "/ui/api/state?section=policy"}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			w := httptest.NewRecorder()
			s.handleState(w, httptest.NewRequest("GET", u, nil))
			if w.Code != 200 {
				t.Errorf("%s: %d %s", u, w.Code, w.Body.String())
			}
		}(urls[i%len(urls)])
	}
	// запись в это время тоже должна проходить
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.st.Update(func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES('w',?,'adm','вход','')`, now)
			return err
		}); err != nil {
			t.Error(err)
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("опросы морды зависли\n%s", buf[:runtime.Stack(buf, true)])
	}
}
