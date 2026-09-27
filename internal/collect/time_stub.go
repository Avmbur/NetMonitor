//go:build !linux

package collect

import "time"

var epoch = time.Now()

func MonotonicMS() int64 { return time.Since(epoch).Milliseconds() }
func Namespace() string  { return "test" }
