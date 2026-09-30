//go:build linux

package collect

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WatchLinks calls fn after a bridge appears or receives an address.
// Events are coalesced for a short moment. The ten-second firewall timer stays as a backstop.
func WatchLinks(stop <-chan struct{}, fn func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		return err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}); err != nil {
		return err
	}
	buf := make([]byte, 65536)
	return watchLinkEvents(stop, func() (bool, error) {
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				return false, nil
			}
			return false, err
		}
		if flags&unix.MSG_TRUNC != 0 {
			return false, errors.New("truncated route netlink message")
		}
		return routeChanged(buf[:n]), nil
	}, fn, time.Now)
}

func routeChanged(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	for _, m := range msgs {
		if RouteEvent(m.Header.Type) {
			return true
		}
	}
	return false
}
