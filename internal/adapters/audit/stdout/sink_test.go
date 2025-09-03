package stdout

import (
	"context"
	"testing"
	"time"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

// testLogger is a minimal in-memory logger to capture logs for assertions.
// It satisfies usecase.Logger and stores level, message, and args.
// Not goroutine-safe beyond basic append guarded by a mutex.
// Levels: debug, info, warn, error.

type logEntry struct {
	level string
	msg   string
	args  []any
}

type testLogger struct {
	logs []logEntry
}

func (t *testLogger) record(level, msg string, args ...any) {
	t.logs = append(t.logs, logEntry{level: level, msg: msg, args: args})
}

func (t *testLogger) Debug(ctx context.Context, msg string, args ...any) {
	t.record("debug", msg, args...)
}
func (t *testLogger) Info(ctx context.Context, msg string, args ...any) {
	t.record("info", msg, args...)
}
func (t *testLogger) Warn(ctx context.Context, msg string, args ...any) {
	t.record("warn", msg, args...)
}
func (t *testLogger) Error(ctx context.Context, msg string, args ...any) {
	t.record("error", msg, args...)
}

func (t *testLogger) With(args ...any) usecase.Logger      { return t }
func (t *testLogger) WithGroup(name string) usecase.Logger { return t }

// compile-time check
var _ usecase.Logger = (*testLogger)(nil)

func hasKey(args []any, key string) bool {
	for i := 0; i+1 < len(args); i += 2 {
		if k, ok := args[i].(string); ok && k == key {
			return true
		}
	}
	return false
}

func countKey(args []any, key string) int {
	n := 0
	for i := 0; i+1 < len(args); i += 2 {
		if k, ok := args[i].(string); ok && k == key {
			n++
		}
	}
	return n
}

func TestSink_Write_SuccessLogsInfo(t *testing.T) {
	tl := &testLogger{}
	s := New(tl)

	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	id := domain.Identity{Subject: "sub1", Username: "alice"}
	serial := uint64(7)
	nb := now.Add(-time.Minute)
	na := now.Add(time.Hour)
	ctx := domain.SignContext{Now: now, SourceIP: "127.0.0.1", TraceID: "trace-1"}
	ev := domain.NewAuditSuccess(domain.ActionIssueUserCert, id, []string{"alice", "devs"}, serial, nb, na, ctx, map[string]string{"env": "test"})

	if err := s.Write(context.Background(), ev); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(tl.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(tl.logs))
	}
	e := tl.logs[0]
	if e.level != "info" || e.msg != "audit_success" {
		t.Fatalf("unexpected log meta: %+v", e)
	}
	// core fields present
	for _, k := range []string{"time", "action", "stage", "trace_id", "subject", "source_ip", "serial"} {
		if !hasKey(e.args, k) {
			t.Errorf("missing key %q", k)
		}
	}
	// principals repeated
	if got := countKey(e.args, "principal"); got != 2 {
		t.Errorf("want 2 principals, got %d", got)
	}
}

func TestSink_Write_FailureLogsWarn(t *testing.T) {
	tl := &testLogger{}
	s := New(tl)

	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	id := domain.Identity{Subject: "sub2", Username: "bob"}
	ctx := domain.SignContext{Now: now, SourceIP: "10.0.0.1", TraceID: "trace-2"}
	ev := domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StagePolicy, id, []string{"bob"}, ctx, domain.ErrPolicyDenied, map[string]string{"reason": "no role"})

	if err := s.Write(context.Background(), ev); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(tl.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(tl.logs))
	}
	e := tl.logs[0]
	if e.level != "warn" || e.msg != "audit_failure" {
		t.Fatalf("unexpected log meta: %+v", e)
	}
	if !hasKey(e.args, "error_code") || !hasKey(e.args, "error_message") {
		t.Errorf("expected error fields present")
	}
	if hasKey(e.args, "serial") {
		t.Errorf("did not expect serial in failure event")
	}
}
