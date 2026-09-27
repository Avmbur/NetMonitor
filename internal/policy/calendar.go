package policy

import (
	"fmt"
	"time"
)

// CalendarBounds maps the date-only «с»/«по» fields onto [from, until).
// «по» is that calendar day inclusive: until is midnight of the next local day.
func CalendarBounds(from, to string, loc *time.Location) (int64, int64, error) {
	if loc == nil {
		loc = time.Local
	}
	end, err := parseDay(to, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("укажи дату «по»")
	}
	until := end.AddDate(0, 0, 1).UnixMilli()
	if from == "" {
		return 0, until, nil
	}
	start, err := parseDay(from, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("неверная дата «с»")
	}
	fromMS := start.UnixMilli()
	if !start.Before(end.AddDate(0, 0, 1)) {
		return 0, 0, fmt.Errorf("дата «по» должна быть не раньше «с»")
	}
	return fromMS, until, nil
}

func parseDay(s string, loc *time.Location) (time.Time, error) {
	return time.ParseInLocation("2006-01-02", s, loc)
}
