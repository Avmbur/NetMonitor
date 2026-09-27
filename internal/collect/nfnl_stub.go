//go:build !linux

package collect

import "fmt"

func DumpNetlink() ([]Entry, error) {
	return nil, fmt.Errorf("ctnetlink только linux")
}

func Watch(stop <-chan struct{}, fn func(Entry, string)) error {
	<-stop
	return nil
}

func WatchReady(stop <-chan struct{}, fn func(Entry, string), ready func()) error {
	ready()
	return Watch(stop, fn)
}
