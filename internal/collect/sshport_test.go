package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHListenPortDefault22(t *testing.T) {
	if p := SSHListenPort(t.TempDir()); p != 22 {
		t.Fatal(p)
	}
}

func TestSSHListenPortFromProc(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(root, "42")
	if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("sshd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[3333]", filepath.Join(pid, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if p := SSHListenPort(root); p != 2222 {
		t.Fatal(p)
	}
	ls := ListeningList(root)
	if len(ls) != 1 || ls[0].Port != 2222 || ls[0].Proto != "tcp" || ls[0].Proc != "sshd" {
		t.Fatal(ls)
	}
}

func TestListeningListSystemdSocketAndServices(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(units, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(root, "1")
	if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1111]", filepath.Join(pid, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	sock := "[Socket]\nListenStream=22\nAccept=yes\n"
	svc := "[Service]\nExecStart=/usr/sbin/sshd -D\n"
	if err := os.WriteFile(filepath.Join(units, "ssh.socket"), []byte(sock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(units, "ssh.service"), []byte(svc), 0o644); err != nil {
		t.Fatal(err)
	}
	svcFile := filepath.Join(root, "services")
	if err := os.WriteFile(svcFile, []byte("ssh\t22/tcp\nhttp\t80/tcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDirs, oldSvc := systemdUnitDirs, servicesPath
	systemdUnitDirs = []string{units}
	servicesPath = svcFile
	resetServiceCache()
	t.Cleanup(func() {
		systemdUnitDirs, servicesPath = oldDirs, oldSvc
		resetServiceCache()
	})
	ls := ListeningList(root)
	if len(ls) != 1 || ls[0].Port != 22 || ls[0].Proc != "sshd" || ls[0].Desc != "ssh" {
		t.Fatal(ls)
	}
}
