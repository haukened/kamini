package domain

import (
	"testing"
	"time"
)

func TestTTLClamp(t *testing.T) {
	tll := TTL{Default: time.Hour, Max: 4 * time.Hour}
	if got := tll.Clamp(0); got != time.Hour {
		t.Fatalf("default clamp = %v", got)
	}
	if got := tll.Clamp(2 * time.Hour); got != 2*time.Hour {
		t.Fatalf("mid clamp = %v", got)
	}
	if got := tll.Clamp(24 * time.Hour); got != 4*time.Hour {
		t.Fatalf("max clamp = %v", got)
	}
}
