package log

import (
	"context"

	"github.com/haukened/kamini/internal/usecase"
)

// NewNop returns a no-op logger that discards all logs.
func NewNop() usecase.Logger { return Nop{} }

// Nop is a no-op implementation of usecase.Logger.
type Nop struct{}

func (Nop) Debug(context.Context, string, ...any) {}
func (Nop) Info(context.Context, string, ...any)  {}
func (Nop) Warn(context.Context, string, ...any)  {}
func (Nop) Error(context.Context, string, ...any) {}

func (Nop) With(...any) usecase.Logger      { return Nop{} }
func (Nop) WithGroup(string) usecase.Logger { return Nop{} }

// Assert that Nop implements usecase.Logger.
var _ usecase.Logger = (*Nop)(nil)
