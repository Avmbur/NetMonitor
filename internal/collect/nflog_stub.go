//go:build !linux

package collect

import "netmonitor/internal/protocol"

func ListenNFLog(stop <-chan struct{}, fn func(protocol.FirewallPayload, Entry), gap func(error)) error {
	<-stop
	return nil
}
func ObserveForeignFirewall() error { return nil }
