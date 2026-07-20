package padding

import (
	"crypto/rand"
	"github.com/ASTRACAT2022/aesingflow/core/errors"
)

type Profile uint8

const (
	Disabled Profile = iota
	Minimal
	Balanced
)

func Add(profile Profile, p []byte, maxOverhead int) ([]byte, int, error) {
	if profile == Disabled {
		return append([]byte(nil), p...), 0, nil
	}
	n := 8
	if profile == Balanced {
		n = 32
	}
	if n > maxOverhead {
		return nil, 0, errors.New(errors.LimitExceeded, "padding overhead exceeds limit")
	}
	b := make([]byte, len(p)+n)
	copy(b, p)
	if _, e := rand.Read(b[len(p):]); e != nil {
		return nil, 0, e
	}
	return b, n, nil
}
