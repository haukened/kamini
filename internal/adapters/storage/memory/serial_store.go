package memory

import (
	"context"
	"sync/atomic"

	"github.com/haukened/kamini/internal/usecase"
)

// MemorySerialStore is an in-memory, process-local serial counter.
// Not durable; suitable for unit tests and local dev only.
type MemorySerialStore struct {
	c atomic.Uint64
	L usecase.Logger
}

var _ usecase.SerialStore = (*MemorySerialStore)(nil)

// NewMemorySerialStore creates a new store with a required logger.
func NewMemorySerialStore(l usecase.Logger) *MemorySerialStore {
	return &MemorySerialStore{L: l}
}

// Next atomically increments the counter and returns the new value.
func (m *MemorySerialStore) Next(ctx context.Context) (uint64, error) {
	n := m.c.Add(1)
	if m.L != nil {
		m.L.Debug(ctx, "serial(memory): advanced", "value", n)
	}
	return n, nil
}
