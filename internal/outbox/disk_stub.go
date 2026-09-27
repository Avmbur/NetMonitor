//go:build !linux

package outbox

func FreeBytes(path string) (uint64, error) { return ^uint64(0), nil }
