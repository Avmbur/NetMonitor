//go:build !linux

package collect

func EnableKernel() error { return nil }
