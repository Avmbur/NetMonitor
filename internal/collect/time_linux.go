//go:build linux

package collect

import (
	"golang.org/x/sys/unix"
	"os"
)

func MonotonicMS() int64 {
	var t unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &t) != nil {
		return 0
	}
	return t.Sec*1000 + t.Nsec/1_000_000
}
func Namespace() string { s, _ := os.Readlink("/proc/self/ns/net"); return s }
