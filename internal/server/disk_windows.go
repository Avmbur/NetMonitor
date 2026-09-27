//go:build windows

package server

import "golang.org/x/sys/windows"

func diskSize(path string) (total, free uint64, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	var freeBytes, totalBytes, totalFree uint64
	err = windows.GetDiskFreeSpaceEx(p, &freeBytes, &totalBytes, &totalFree)
	return totalBytes, freeBytes, err
}
