//go:build linux

package collect

import "golang.org/x/sys/unix"

func netRetry(err error) bool {
	return err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR
}
