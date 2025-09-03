# In-memory SerialStore

Purpose
- Fast, non-durable serial allocator for unit tests and local development.
- Not safe across processes, not persisted across restarts.

How it works
- Uses an atomic counter in memory.
- Each call to Next() atomically increments and returns the next value starting at 1.

Usage (Go)
```go
import memstore "github.com/haukened/kamini/internal/adapters/storage/memory"

s := memstore.NewMemorySerialStore(logger)
serial, _ := s.Next(ctx)
```

Caveats
- Not durable: restarts reset the counter to 0.
- Not suitable for production where serials must be unique over time and across processes.

Testing
- See `serial_store_test.go` for sequential and concurrent uniqueness tests.
