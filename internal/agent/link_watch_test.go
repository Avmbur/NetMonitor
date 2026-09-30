package agent

import (
	"errors"
	"testing"
	"time"
)

func TestLinkWatchReconnects(t *testing.T) {
	stop := make(chan struct{})
	calls := 0
	retryLinkWatch(stop, 0, func() error {
		calls++
		if calls < 3 {
			return errors.New("socket lost")
		}
		return nil
	})
	if calls != 3 {
		t.Fatalf("watch called %d times, want 3", calls)
	}
}

func TestLinkWatchStopDuringRetry(t *testing.T) {
	stop := make(chan struct{})
	failed := make(chan struct{})
	done := make(chan struct{})
	calls := 0
	go func() {
		defer close(done)
		retryLinkWatch(stop, time.Hour, func() error {
			calls++
			if calls == 1 {
				close(failed)
			}
			return errors.New("socket lost")
		})
	}()
	<-failed
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop waited for retry delay")
	}
	if calls != 1 {
		t.Fatalf("watch restarted after stop: %d calls", calls)
	}
	retryLinkWatch(stop, 0, func() error {
		t.Fatal("opened watcher after stop")
		return nil
	})
}
