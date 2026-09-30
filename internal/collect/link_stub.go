//go:build !linux

package collect

// WatchLinks is a no-op where route netlink is not used. The firewall timer still refreshes bridges.
func WatchLinks(stop <-chan struct{}, fn func()) error {
	<-stop
	return nil
}
