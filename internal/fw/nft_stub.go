//go:build !linux

package fw

func listLearnHits() []LearnHit { return nil }

func prepareNft(Policy) error { return nil }
