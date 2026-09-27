package policy

import (
	"testing"
	"time"
)

func TestCalendarBoundsCoverTheLocalDay(t *testing.T) {
	loc := time.FixedZone("MSK", 3*3600)
	from, until, err := CalendarBounds("2026-09-22", "2026-09-22", loc)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 22, 0, 0, 0, 0, loc)
	if from != start.UnixMilli() || until != start.AddDate(0, 0, 1).UnixMilli() {
		t.Fatal(from, until)
	}
	r := Rule{Enabled: true, Action: "allow", FromMS: from, UntilMS: until, Match: Match{Networks: []string{"198.18.0.2/32"}}}
	c := Contact{RemoteIP: "198.18.0.2"}
	before := start.Add(-time.Millisecond).UnixMilli()
	last := start.Add(24*time.Hour - time.Millisecond).UnixMilli()
	if _, ok := Evaluate([]Rule{r}, "h", c, before); ok {
		t.Fatal("active before the local day")
	}
	if _, ok := Evaluate([]Rule{r}, "h", c, from); !ok {
		t.Fatal("inactive at local midnight")
	}
	if _, ok := Evaluate([]Rule{r}, "h", c, last); !ok {
		t.Fatal("inactive inside the local day")
	}
	if _, ok := Evaluate([]Rule{r}, "h", c, until); ok {
		t.Fatal("active after the local day")
	}
	if _, _, err = CalendarBounds("2026-09-23", "2026-09-22", loc); err == nil {
		t.Fatal("inverted range")
	}
}
