package domain

import (
	"fmt"
	"time"
)

// SignContext carries environment details the policy might care about (no IO).
type SignContext struct {
	RequestedTTL   time.Duration
	RequestedHints []string // optional principals hints from client (non-authoritative)
	SourceIP       string
	Now            time.Time
	TraceID        string
}

// PolicyDecision is the *result* of authorization.
type PolicyDecision struct {
	Principals      []string
	TTL             time.Duration
	CriticalOptions map[string]string
	Extensions      map[string]string
}

// Helper to compose KeyID deterministically (for audit/search).
func ComposeKeyID(id Identity, serial uint64) string {
	// e.g., "<serial>|<subject>|<username>"
	// Avoid PII beyond what's useful; keep consistent for logs.
	return fmt.Sprintf("%d|%s|%s", serial, id.Subject, id.Username)
}

// DenyCode is a stable, non-PII reason for policy denial.
type DenyCode string

const (
	DenyPrincipalNotAllowed DenyCode = "PRINCIPAL_NOT_ALLOWED"
	DenyTTLTooLarge         DenyCode = "TTL_TOO_LARGE"
	DenyTTLTooSmall         DenyCode = "TTL_TOO_SMALL"
	DenyIPNotAllowed        DenyCode = "IP_NOT_ALLOWED"
	DenyRoleMissing         DenyCode = "ROLE_MISSING"
	DenyQuotaExceeded       DenyCode = "QUOTA_EXCEEDED"
	DenyDefault             DenyCode = "DEFAULT_DENY"
)

// PolicyDeny represents a structured policy denial.
type PolicyDeny struct {
	Code    DenyCode
	Message string // short, public message; avoid PII/secrets
}

func (e PolicyDeny) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

// DenyAttrs returns canonical audit attributes for a policy denial.
func DenyAttrs(e PolicyDeny) map[string]string {
	return map[string]string{"deny_code": string(e.Code)}
}
