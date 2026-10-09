package tlsutil

import (
	"os"
	"path/filepath"
)

// Каталог копии удостоверения монитора. Он лежит рядом с каталогом данных,
// поэтому новая установка базы может вернуть тот же центр сертификации.
// Агент проверяет монитор по этому центру и не принимает чужой ключ.
func BackupDir() string {
	if d := os.Getenv("NM_TRUST_DIR"); d != "" {
		return d
	}
	return "/var/lib/nm-trust"
}

// UseBackup говорит, копировать ли удостоверение. В тестах каталог включается
// переменной NM_TRUST_DIR. На мониторе копия ведётся только у боевого каталога,
// чтобы прогон не писал ключ в /var/lib.
func UseBackup(dataDir string) bool {
	if os.Getenv("NM_TRUST_DIR") != "" {
		return true
	}
	return filepath.Clean(dataDir) == filepath.Clean("/var/lib/nmserver")
}

// RestoreTrust кладёт сохранённый центр в каталог данных, если своего ещё нет.
func RestoreTrust(dataDir string) error {
	if !UseBackup(dataDir) {
		return nil
	}
	dst := filepath.Join(dataDir, "tls")
	if fileExists(filepath.Join(dst, "ca.key")) {
		return nil
	}
	src := BackupDir()
	if !fileExists(filepath.Join(src, "ca.key")) || !fileExists(filepath.Join(src, "ca.crt")) {
		return nil
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return copyTrust(src, dst)
}

// MirrorTrust обновляет копию по живому центру монитора.
func MirrorTrust(dataDir string) error {
	if !UseBackup(dataDir) {
		return nil
	}
	src := filepath.Join(dataDir, "tls")
	if !fileExists(filepath.Join(src, "ca.key")) || !fileExists(filepath.Join(src, "ca.crt")) {
		return nil
	}
	dst := BackupDir()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return copyTrust(src, dst)
}

func copyTrust(src, dst string) error {
	for _, name := range []string{"ca.crt", "ca.key"} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if name == "ca.key" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dst, name), b, mode); err != nil {
			return err
		}
	}
	return nil
}
