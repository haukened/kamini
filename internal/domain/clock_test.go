package domain

import (
	"testing"
	"time"
)

func TestSystemClock_Now(t *testing.T) {
	clk := SystemClock()
	got := clk.Now()
	if got.Location() != time.UTC {
		t.Fatalf("SystemClock.Now() location = %v, want UTC", got.Location())
	}
	// Check that the returned time is close to time.Now().UTC()
	now := time.Now().UTC()
	diff := got.Sub(now)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("SystemClock.Now() = %v, want close to %v (diff %v)", got, now, diff)
	}
}
