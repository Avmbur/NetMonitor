//go:build !linux

package collect

func ConntrackFailures() (map[string]uint64, error) { return map[string]uint64{}, nil }
