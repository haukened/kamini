package file

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	ilog "github.com/haukened/kamini/internal/log"
)

func TestFileSerialStoreSequentialAndResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serial.txt")

	ctx := context.Background()

	s, err := NewFileSerialStore(path, ilog.NewNop())
	if err != nil {
		t.Fatalf("NewFileSerialStore: %v", err)
	}

	var last uint64
	for i := 1; i <= 3; i++ {
		serial, err := s.Next(ctx)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		last = serial
		if got, want := int(serial), i; got != want {
			t.Fatalf("serial=%d, want=%d", got, want)
		}
	}

	s2, err := NewFileSerialStore(path, ilog.NewNop())
	if err != nil {
		t.Fatalf("NewFileSerialStore(second): %v", err)
	}
	serial, err := s2.Next(ctx)
	if err != nil {
		t.Fatalf("Next(second): %v", err)
	}
	if serial != last+1 {
		t.Fatalf("resume serial=%d, want=%d", serial, last+1)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat serial file: %v", err)
	}
}

func TestFileSerialStoreConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serial.txt")
	ctx := context.Background()

	s, err := NewFileSerialStore(path, ilog.NewNop())
	if err != nil {
		t.Fatalf("NewFileSerialStore: %v", err)
	}

	const N = 50
	out := make(chan uint64, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			v, err := s.Next(ctx)
			if err != nil {
				t.Errorf("Next error: %v", err)
				return
			}
			out <- v
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
