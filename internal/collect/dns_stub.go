//go:build !linux

package collect

func ListenDNS(stop <-chan struct{}, fn func(DNSRecord)) error {
	<-stop
	return nil
}
