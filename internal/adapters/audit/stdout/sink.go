package stdout

import (
	"context"
	"time"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

// Sink writes audit events using the injected structured logger.
// Intended for MVP where stdout logging is sufficient; future sinks
// can persist to a DB without altering use cases.
type Sink struct {
	L usecase.Logger
}

var _ usecase.AuditSink = (*Sink)(nil)

// New creates a new stdout-backed audit sink.
func New(l usecase.Logger) *Sink {
	if l != nil {
		l = l.WithGroup("audit")
	}
	return &Sink{L: l}
}

// Write emits a structured audit log line.
// Success events are logged at Info; failure events at Warn.
func (s *Sink) Write(ctx context.Context, ev domain.AuditEvent) error {
	if s.L == nil {
		return nil
	}
	args := eventAttrs(ev)
	if ev.Success() {
		s.L.Info(ctx, "audit_success", args...)
	} else {
		s.L.Warn(ctx, "audit_failure", args...)
	}
	return nil
}

func eventAttrs(ev domain.AuditEvent) []any {
	attrs := []any{
		"time", ev.Time.Format(time.RFC3339Nano),
		"action", string(ev.Action),
		"stage", string(ev.Stage),
		"trace_id", ev.TraceID,
		"subject", ev.Subject,
		"source_ip", ev.SourceIP,
	}
	if len(ev.Principals) > 0 {
		// Log principals as repeated key for compatibility with slog.
		for _, p := range ev.Principals {
			attrs = append(attrs, "principal", p)
		}
	}
	if ev.Serial != nil {
		attrs = append(attrs, "serial", *ev.Serial)
	}
	if ev.NotBefore != nil {
		attrs = append(attrs, "not_before", ev.NotBefore.UTC().Format(time.RFC3339))
	}
	if ev.NotAfter != nil {
		attrs = append(attrs, "not_after", ev.NotAfter.UTC().Format(time.RFC3339))
	}
	if ev.KeyFP != "" {
		attrs = append(attrs, "key_fp", ev.KeyFP)
	}
	if ev.KeyID != "" {
		attrs = append(attrs, "key_id", ev.KeyID)
	}
	if ev.ErrorCode != "" {
		attrs = append(attrs, "error_code", string(ev.ErrorCode))
	}
	if ev.ErrorMessage != "" {
		attrs = append(attrs, "error_message", ev.ErrorMessage)
	}
	if len(ev.Attrs) > 0 {
		for k, v := range ev.Attrs {
			attrs = append(attrs, "attr_"+k, v)
		}
	}
	return attrs
}
