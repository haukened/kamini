package memory

import (
	"context"
	"sync"
	"testing"

	ilog "github.com/haukened/kamini/internal/log"
)

func TestMemorySerialStoreSequential(t *testing.T) {
	s := NewMemorySerialStore(ilog.NewNop())
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		serial, err := s.Next(ctx)
		if err != nil {
			t.Fatalf("Next error: %v", err)
		}
		if got, want := int(serial), i; got != want {
			t.Fatalf("serial=%d, want=%d", got, want)
		}
	}
}

func TestMemorySerialStoreConcurrent(t *testing.T) {
	s := NewMemorySerialStore(ilog.NewNop())
	ctx := context.Background()

	const N = 200
	out := make(chan uint64, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			serial, err := s.Next(ctx)
			if err != nil {
				t.Errorf("Next error: %v", err)
				return
			}
			out <- serial
		}()
	}
	wg.Wait()
	close(out)

	seen := make(map[uint64]struct{}, N)
	for v := range out {
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate serial: %d", v)
		}
		seen[v] = struct{}{}
	}
	if len(seen) != N {
		t.Fatalf("got %d unique serials, want %d", len(seen), N)
	}
}
