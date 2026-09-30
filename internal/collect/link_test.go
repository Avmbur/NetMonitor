package collect

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestLinkEventsBatchDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changed func(int) bool
		want    []int
	}{
		{"continuous", func(int) bool { return true }, []int{0, 4, 8, 12}},
		{"burst then idle", func(tick int) bool { return tick <= 2 }, []int{0, 4}},
		{"unrelated events", func(int) bool { return false }, []int{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := make(chan struct{})
			tick := 0
			var applied []int
			err := watchLinkEvents(stop, func() (bool, error) {
				tick++
				if tick == 13 {
					close(stop)
				}
				return tc.changed(tick), nil
			}, func() {
				applied = append(applied, tick)
			}, func() time.Time {
				return time.Unix(0, 0).Add(time.Duration(tick) * 100 * time.Millisecond)
			})
			if err != nil || !reflect.DeepEqual(applied, tc.want) {
				t.Fatalf("applied at %v, want %v; error: %v", applied, tc.want, err)
			}
		})
	}
}

func TestLinkEventsReceiveFailureAndResubscribe(t *testing.T) {
	stop := make(chan struct{})
	failure := errors.New("socket lost")
	applied := 0
	tick := 0
	err := watchLinkEvents(stop, func() (bool, error) {
		tick++
		if tick == 1 {
			return true, nil
		}
		return false, failure
	}, func() { applied++ }, time.Now)
	if !errors.Is(err, failure) || applied != 1 {
		t.Fatalf("error %v, applications %d", err, applied)
	}
	// A new subscription must reconcile the lost pending batch immediately.
	err = watchLinkEvents(stop, func() (bool, error) {
		close(stop)
		return false, nil
	}, func() { applied++ }, time.Now)
	if err != nil || applied != 2 {
		t.Fatalf("resubscribe: error %v, applications %d", err, applied)
	}
	err = watchLinkEvents(stop, func() (bool, error) {
		t.Fatal("read after stop")
		return false, nil
	}, func() { t.Fatal("apply after stop") }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
}
