package domain

import (
	"errors"
	"time"
)

// AuditAction identifies the high-level action being recorded.
type AuditAction string

const (
	// ActionIssueUserCert is emitted when attempting/issuing a user certificate.
	ActionIssueUserCert AuditAction = "ISSUE_USER_CERT"
	// ActionDeny is emitted when a request is denied by policy/authorization.
	ActionDeny AuditAction = "DENY"
	// ActionError is emitted for unexpected/unhandled errors.
	ActionError AuditAction = "ERROR"
)

// AuditStage identifies where in the flow an event occurred.
type AuditStage string

const (
	StageUnknown AuditStage = "UNKNOWN"
	StageAuthn   AuditStage = "AUTHN"
	StageAuthz   AuditStage = "AUTHZ"
	StagePolicy  AuditStage = "POLICY"
	StageSign    AuditStage = "SIGN"
	StageInput   AuditStage = "INPUT" // request validation/normalization
)

// AuditEvent is a pure fact. Adapters serialize/ship it; usecases emit it.
// It covers both success and failure cases. For failures, Stage/ErrorCode/ErrorMessage
// should be set, and Serial/validity fields may be nil.
type AuditEvent struct {
	Time         time.Time
	Action       AuditAction // high-level action
	Stage        AuditStage
	TraceID      string // correlation id for joining with request logs
	Subject      string
	Principals   []string
	Serial       *uint64
	NotBefore    *time.Time // UTC
	NotAfter     *time.Time // UTC
	KeyFP        string
	KeyID        string // certificate KeyId (for operator search)
	SourceIP     string
	ErrorCode    ErrorCode         // stable, non-PII code (e.g., "POLICY_DENIED")
	ErrorMessage string            // short, safe-to-log message (no secrets)
	Attrs        map[string]string // misc (plugin names, hints, correlation ids)
}

// Success reports whether this event represents a successful outcome
// (i.e., no error code was recorded).
func (e AuditEvent) Success() bool { return e.ErrorCode == "" }

// Validate enforces success/failure invariants.
func (e AuditEvent) Validate() error {
	if e.Success() {
		if e.Serial == nil || e.NotBefore == nil || e.NotAfter == nil {
			return errors.New("success event requires serial and validity window")
		}
		if e.ErrorCode != "" || e.ErrorMessage != "" {
			return errors.New("success event must not contain error fields")
		}
		return nil
	}
	// failure
	if e.Serial != nil || e.NotBefore != nil || e.NotAfter != nil || e.KeyFP != "" || e.KeyID != "" {
		return errors.New("failure event must not contain success-only fields")
	}
	return nil
}

// ErrorCode is a stable, non-PII code describing an error.
type ErrorCode string

const (
	CodeMissingPublicKey ErrorCode = "MISSING_PUBLIC_KEY"
	CodeNoPrincipals     ErrorCode = "NO_PRINCIPALS"
	CodeInvalidValidity  ErrorCode = "INVALID_VALIDITY"
	CodePolicyDenied     ErrorCode = "POLICY_DENIED"
	CodeUnknownError     ErrorCode = "UNKNOWN_ERROR"
)

// NewAuditFailure creates a failure event with best-effort error classification.
// - action: the high-level action attempted (e.g., ActionIssueUserCert).
// - stage: where it failed (AUTHN/AUTHZ/POLICY/SIGN/INPUT).
// - id/principals: identity context and any candidate principals (may be empty).
// - ctx: request context (used for Time and SourceIP).
// - err: the error that caused the failure (classified to a stable code/message).
// - attrs: optional extra attributes (merged into event).
func NewAuditFailure(action AuditAction, stage AuditStage, id Identity, principals []string, ctx SignContext, err error, attrs map[string]string) AuditEvent {
	code, msg := ClassifyError(err)
	return AuditEvent{
		Time:         ctx.Now,
		Action:       action,
		Stage:        stage,
		TraceID:      ctx.TraceID,
		Subject:      id.Subject,
		Principals:   cloneStringSlice(principals),
		SourceIP:     ctx.SourceIP,
		ErrorCode:    code,
		ErrorMessage: msg,
		Attrs:        cloneStringMap(attrs),
	}
}

// NewAuditSuccess creates a success event with serial/validity filled in.
// - action: the high-level action performed (e.g., ActionIssueUserCert).
// - id/principals: identity context and the issued principals.
// - serial/nb/na: certificate serial and validity window (UTC).
// - ctx: request context (used for Time and SourceIP).
// - attrs: optional extra attributes (merged into event).
func NewAuditSuccess(action AuditAction, id Identity, principals []string, serial uint64, nb, na time.Time, ctx SignContext, attrs map[string]string) AuditEvent {
	return AuditEvent{
		Time:       ctx.Now,
		Action:     action,
		Stage:      StageSign,
		TraceID:    ctx.TraceID,
		Subject:    id.Subject,
		Principals: cloneStringSlice(principals),
		Serial:     &serial,
		NotBefore:  &nb,
		NotAfter:   &na,
		SourceIP:   ctx.SourceIP,
		Attrs:      cloneStringMap(attrs),
	}
}

// ClassifyError maps known domain errors to stable codes and public messages.
// Unknown errors return ("UNKNOWN_ERROR", err.Error()). The message should be
// safe to log; callers remain responsible for avoiding secrets in wrapped errors.
func ClassifyError(err error) (code ErrorCode, publicMessage string) {
	if err == nil {
		return "", ""
	}
	var pd PolicyDeny
	if errors.As(err, &pd) {
		if pd.Message == "" {
			return CodePolicyDenied, "policy denied"
		}
		return CodePolicyDenied, pd.Message
	}
	switch {
	case errors.Is(err, ErrMissingPublicKey):
		return CodeMissingPublicKey, "missing public key"
	case errors.Is(err, ErrNoPrincipals):
		return CodeNoPrincipals, "no principals"
	case errors.Is(err, ErrInvalidValidity):
		return CodeInvalidValidity, "invalid validity window"
	case errors.Is(err, ErrPolicyDenied):
		return CodePolicyDenied, "policy denied issuance"
	default:
		return CodeUnknownError, "unexpected error"
	}
}
