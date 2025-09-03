package log

import (
	"context"
	stdslog "log/slog"

	"github.com/haukened/kamini/internal/usecase"
)

// Slog wraps a slog.Logger to satisfy bootstrap.Logger.
type Slog struct{ l *stdslog.Logger }

// New returns a usecase.Logger backed by the provided slog.Logger.
func New(l *stdslog.Logger) usecase.Logger { return &Slog{l: l} }

func (s *Slog) Debug(ctx context.Context, msg string, args ...any) {
	s.l.DebugContext(ctx, msg, args...)
}
func (s *Slog) Info(ctx context.Context, msg string, args ...any) { s.l.InfoContext(ctx, msg, args...) }
func (s *Slog) Warn(ctx context.Context, msg string, args ...any) { s.l.WarnContext(ctx, msg, args...) }
func (s *Slog) Error(ctx context.Context, msg string, args ...any) {
	s.l.ErrorContext(ctx, msg, args...)
}

func (s *Slog) With(args ...any) usecase.Logger      { return &Slog{l: s.l.With(args...)} }
func (s *Slog) WithGroup(name string) usecase.Logger { return &Slog{l: s.l.WithGroup(name)} }
