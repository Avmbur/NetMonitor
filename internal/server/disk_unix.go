//go:build unix

package server

import "golang.org/x/sys/unix"

func diskSize(path string) (total, free uint64, err error) {
	var st unix.Statfs_t
	if err = unix.Statfs(path, &st); err != nil {
		return
	}
	bs := uint64(st.Bsize)
	return uint64(st.Blocks) * bs, uint64(st.Bavail) * bs, nil
}
