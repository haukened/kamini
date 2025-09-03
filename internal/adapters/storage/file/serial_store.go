package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/haukened/kamini/internal/usecase"
)

// FileSerialStore persists serial numbers to a file using fsync+rename and a lock file.
type FileSerialStore struct {
	path     string
	lockPath string
	L        usecase.Logger
	mu       sync.Mutex
}

var _ usecase.SerialStore = (*FileSerialStore)(nil)

// NewFileSerialStore creates a file-backed serial store at the given file path.
func NewFileSerialStore(path string, l usecase.Logger) (*FileSerialStore, error) {
	if path == "" {
		return nil, errors.New("path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	return &FileSerialStore{path: path, lockPath: path + ".lock", L: l}, nil
}

// Next reads current value, increments, and writes back atomically.
func (f *FileSerialStore) Next(ctx context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	unlock, err := f.acquireLock()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := unlock(); err != nil && f.L != nil {
			f.L.Warn(ctx, "release lock failed", "error", err)
		}
	}()

	cur, err := f.read()
	if err != nil {
		if f.L != nil {
			f.L.Error(ctx, "read serial failed", "error", err)
		}
		return 0, err
	}
	next := cur + 1
	if err := f.write(next); err != nil {
		if f.L != nil {
			f.L.Error(ctx, "write serial failed", "serial", next, "error", err)
		}
		return 0, err
	}
	if f.L != nil {
		f.L.Debug(ctx, "serial allocated (file)", "serial", next, "path", f.path)
	}
	return next, nil
}

func (f *FileSerialStore) acquireLock() (func() error, error) {
	lf, err := os.OpenFile(f.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("serial store locked: %s", f.lockPath)
		}
		return nil, fmt.Errorf("create lock: %w", err)
	}
	// best effort info
	_, _ = io.WriteString(lf, fmt.Sprintf("pid=%d\n", os.Getpid()))
	_ = lf.Close()
	return func() error { return os.Remove(f.lockPath) }, nil
}

func (f *FileSerialStore) read() (uint64, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	// trim spaces/newlines manually
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	j := len(b)
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	if i >= j {
		return 0, nil
	}
	v, err := strconv.ParseUint(string(b[i:j]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}
	return v, nil
}

func (f *FileSerialStore) write(v uint64) error {
	tmp := f.path + ".tmp"
	fd, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	if _, err := io.WriteString(fd, strconv.FormatUint(v, 10)+"\n"); err != nil {
		_ = fd.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := fd.Sync(); err != nil {
		_ = fd.Close()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := fd.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// optional: fsync dir for stronger guarantees
	if dfd, err := os.Open(filepath.Dir(f.path)); err == nil {
		_ = dfd.Sync()
		_ = dfd.Close()
	}
	return nil
}
