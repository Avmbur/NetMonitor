package server

import (
	"database/sql"
	"netmonitor/internal/protocol"
	"testing"
)

func TestLocalPauseScopedIdempotentAndAtomic(t *testing.T) {
	s, _ := batchFixture(t)
	_, err := s.st.DB.Exec("INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms) VALUES('b','all','198.18.0.2',zeroblob(16),'both','active','test','cli','test',1)")
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.LocalUnblock{RequestID: "report", BlockIDs: []string{"b"}, Reason: "rollback"}
	if err = s.pauseBlocks("a", req); err != nil {
		t.Fatal(err)
	}
	if err = s.pauseBlocks("a", req); err != nil {
		t.Fatal(err)
	}
	var n, rev int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM block_pause").Scan(&n)
	s.st.DB.QueryRow("SELECT policy_rev FROM agents WHERE agent_id='a'").Scan(&rev)
	if n != 1 || rev != 1 {
		t.Fatal("replay duplicated", n, rev)
	}
	pr, err := s.pollSnapshot("a", "trusted", 0)
	if err != nil || len(pr.Blocks) != 0 {
		t.Fatal("paused returned", pr, err)
	}
	req.BlockIDs = []string{"different"}
	if err = s.pauseBlocks("a", req); err == nil {
		t.Fatal("request_id reused")
	}
	s.st.DB.Exec("DELETE FROM block_pause")
	s.st.DB.Exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'full'); END")
	req = protocol.LocalUnblock{RequestID: "next", BlockIDs: []string{"b"}, Reason: "rollback"}
	if err = s.pauseBlocks("a", req); err == nil {
		t.Fatal("failure hidden")
	}
	s.st.DB.QueryRow("SELECT COUNT(*) FROM block_pause").Scan(&n)
	if n != 0 {
		t.Fatal("partial pause")
	}
	var receipt string
	if e := s.st.DB.QueryRow("SELECT v FROM settings WHERE k='local_pause:a:next'").Scan(&receipt); e != sql.ErrNoRows {
		t.Fatal("failed report ACKed", e)
	}
}

func TestConsoleUnblockDoesNotStick(t *testing.T) {
	s, _ := batchFixture(t)
	if _, err := s.st.DB.Exec("INSERT INTO blocks(block_id,scope_kind,remote_ip,remote_ip_bin,direction,state,reason,source,created_by,created_at_ms) VALUES('b','all','198.18.0.2',zeroblob(16),'both','active','test','cli','test',1)"); err != nil {
		t.Fatal(err)
	}
	req := protocol.LocalUnblock{RequestID: "console", BlockIDs: []string{"b"}}
	if err := s.pauseBlocks("a", req); err != nil {
		t.Fatal(err)
	}
	var n, alerts int
	s.st.DB.QueryRow("SELECT COUNT(*) FROM block_pause").Scan(&n)
	s.st.DB.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alerts)
	if n != 0 || alerts != 0 {
		t.Fatalf("console unblock stuck pauses=%d alerts=%d", n, alerts)
	}
}
