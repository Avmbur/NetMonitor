package collect

import "time"

// RouteEvent reports a netlink message that can change a Docker bridge or its address.
// 16/17 are link new/del, 20/21 are address new/del. These numbers are the Linux rtnetlink types.
func RouteEvent(typ uint16) bool {
	switch typ {
	case 16, 17, 20, 21:
		return true
	default:
		return false
	}
}

// receive must return periodically, even when there are no events.
func watchLinkEvents(stop <-chan struct{}, receive func() (bool, error), fn func(), now func() time.Time) error {
	select {
	case <-stop:
		return nil
	default:
	}
	// The subscription is already live. Reconcile changes missed before it opened.
	fn()
	var due time.Time
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		changed, err := receive()
		if err != nil {
			return err
		}
		select {
		case <-stop:
			return nil
		default:
		}
		at := now()
		if changed && due.IsZero() {
			due = at.Add(300 * time.Millisecond)
		}
		// Later events must not postpone an existing batch, even on a busy socket.
		if !due.IsZero() && !at.Before(due) {
			due = time.Time{}
			fn()
		}
	}
}
