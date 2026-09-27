package collect

import "time"

type Snapshot struct {
	When       time.Time
	Flows      int
	Note       string
	Incomplete bool
}

type Source interface {
	Dump() (Snapshot, error)
}
