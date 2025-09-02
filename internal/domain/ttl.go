package domain

import "time"

type TTL struct {
	Default time.Duration
	Max     time.Duration
}

// Clamp returns a sane TTL given a client request.
func (t TTL) Clamp(requested time.Duration) time.Duration {
	if requested <= 0 {
		requested = t.Default
	}
	if t.Max > 0 && requested > t.Max {
		return t.Max
	}
	return requested
}
