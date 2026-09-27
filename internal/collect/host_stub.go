//go:build !linux

package collect

func HostResources() Resources { return Resources{} }
