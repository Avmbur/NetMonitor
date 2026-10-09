package server

import (
	"testing"

	"netmonitor/internal/store"
)

func TestDisplayProc(t *testing.T) {
	if got := displayProc("sshd", ""); got != "sshd" {
		t.Fatalf("comm %q", got)
	}
	if got := displayProc("", "/usr/bin/fwupdmgr"); got != "fwupdmgr" {
		t.Fatalf("path %q", got)
	}
	if got := displayProc("", "cgroup=system.slice/nginx.service"); got != "" {
		t.Fatalf("cgroup %q", got)
	}
	if got := displayProc("https", "/usr/lib/apt/methods/http uid=42 cgroup=system.slice/esm-cache.service"); got != "apt" {
		t.Fatalf("apt %q", got)
	}
	if got := displayProc("http", "/usr/lib/apt/methods/http uid=42 cgroup=system.slice/apt-daily.service"); got != "apt" {
		t.Fatalf("apt http %q", got)
	}
	if got := displayProc("", "/usr/sbin/sshd uid=0 cgroup=system.slice/ssh.service"); got != "sshd" {
		t.Fatalf("path wins %q", got)
	}
	if got := displayProc("check-new-relea", "/usr/bin/python3.14 uid=0 cgroup=user.slice/user-1001.slice/session-304.scope"); got != "python3.14" {
		t.Fatalf("python %q", got)
	}
	if got := displayProc("ядро", ""); got != "" {
		t.Fatalf("fake %q", got)
	}
	if got := displayProc("", ""); got != "" {
		t.Fatalf("empty %q", got)
	}
}

func TestQuestionProcessDoesNotComeFromFlows(t *testing.T) {
	st, err := store.OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.DB.Exec(`INSERT INTO hosts(host_id,hostname,first_seen_ms,last_seen_ms) VALUES('h','test',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`INSERT INTO agents(agent_id,host_id,cert_fingerprint,trust_state,first_seen_ms) VALUES('a','h','fp','trusted',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,proc_comm,proc_path,status)
		VALUES('own','h','own',1,1,2,'out','tcp','203.0.113.9',443,'curl','/usr/bin/curl','open')`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,repeats,last_seen_ms,direction,protocol,remote_ip,remote_port,status)
		VALUES('empty','h','empty',1,1,2,'out','tcp','198.51.100.8',80,'open')`); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB.Exec(`INSERT INTO flows(flow_uid,host_id,agent_id,boot_id,first_seen_at_ms,last_seen_at_ms,ip_version,protocol,orig_src_ip,orig_src_ip_bin,orig_dst_ip,orig_dst_ip_bin,direction,local_ip,local_ip_bin,local_port,remote_ip,remote_ip_bin,remote_port,remote_scope,origin,received_at_ms,proc_comm,proc_path)
		VALUES('f1','h','a','b',1,2,4,'tcp','10.0.0.1',zeroblob(16),'198.51.100.8',zeroblob(16),'out','10.0.0.1',zeroblob(16),41000,'198.51.100.8',zeroblob(16),80,'internet','host',2,'nginx','/usr/sbin/nginx')`); err != nil {
		t.Fatal(err)
	}
	s := &Server{st: st}
	db := &checkedRead{db: st.DB}
	qs := s.listQuestions(db, "", false)
	if db.err != nil {
		t.Fatal(db.err)
	}
	got := map[string]string{}
	for _, q := range qs {
		got[q.ID] = q.Proc
	}
	if got["own"] != "curl" || got["empty"] != "\u2014" {
		t.Fatalf("%+v", got)
	}
}

func TestNtpUbuntuName(t *testing.T) {
	if got := ntpUbuntuName("185.125.190.121", "udp", 123); got != "ntp.ubuntu.com" {
		t.Fatalf("pool %q", got)
	}
	if got := ntpUbuntuName("91.189.91.111", "udp", 123); got != "ntp.ubuntu.com" {
		t.Fatalf("pool2 %q", got)
	}
	if got := ntpUbuntuName("185.125.190.36", "tcp", 443); got != "" {
		t.Fatalf("https %q", got)
	}
	if got := ntpUbuntuName("1.1.1.1", "udp", 123); got != "" {
		t.Fatalf("other %q", got)
	}
}
