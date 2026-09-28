//go:build !linux

package fw

func listLearnHits() []LearnHit { return nil }

func prepareNft(Policy) (map[string]uint64, error) { return nil, nil }

func cgroupsMoved(map[string]uint64) bool { return false }
