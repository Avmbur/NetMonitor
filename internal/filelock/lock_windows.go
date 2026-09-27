package filelock

import (
	"golang.org/x/sys/windows"
	"os"
)

func Acquire(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	ov := new(windows.Overlapped)
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ov); e != nil {
		f.Close()
		return nil, e
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ov); f.Close() }, nil
}
