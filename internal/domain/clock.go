package domain

import "time"

// Clock makes time testable.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func SystemClock() Clock { return systemClock{} }
