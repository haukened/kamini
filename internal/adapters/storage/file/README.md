# File-backed SerialStore

Purpose
- Durable certificate serial allocator persisted to a single file.
- Suitable for single-node deployments; survives process restarts and crashes.

How it works
- Serial value is stored as text in a file (e.g., `.../serial.txt`).
- Next():
	- Acquires a lockfile `<path>.lock` (O_CREATE|O_EXCL) to prevent concurrent writers.
	- Reads current value (missing file = 0).
	- Writes the next value to `<path>.tmp`, calls fsync, then atomically renames to `<path>`.
	- Optionally fsyncs the parent directory (best effort) to strengthen durability.

Concurrency and safety
- In-process safety via a mutex.
- Cross-process coordination via a best-effort lockfile. If the lock exists, callers receive an error and may retry.
- Atomic rename ensures readers never see partial writes.

Usage (Go)
```go
import filestore "github.com/haukened/kamini/internal/adapters/storage/file"

s, err := filestore.NewFileSerialStore("/var/lib/kamini/serial.txt", logger)
if err != nil { /* handle */ }
next, err := s.Next(ctx)
```

Operational notes
- Ensure the process user can create and write to the target directory.
- For multi-node deployments, prefer a centralized store (e.g., SQL) rather than a shared filesystem.
- If the process crashes while holding the lockfile, you may need to remove `<path>.lock`. A future enhancement could add staleness detection with timestamps.

Testing
- See `serial_store_test.go` for persistence and concurrency tests.

