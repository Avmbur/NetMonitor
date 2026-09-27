//go:build linux

package outbox

import "golang.org/x/sys/unix"

func FreeBytes(path string) (uint64, error) {
	var s unix.Statfs_t
	e := unix.Statfs(path, &s)
	return s.Bavail * uint64(s.Bsize), e
}
