package usecase

import (
	"context"
	"time"

	"github.com/haukened/kamini/internal/domain"
)

// Clock is the injected time source for application flows (alias to domain.Clock).
// All usecases should rely on this, never time.Now() directly.
type Clock = domain.Clock

// Authorizer decides principals/ttl/options based on identity and context.
// Implementations live in adapters.
type Authorizer interface {
	Decide(id domain.Identity, ctx domain.SignContext) (domain.PolicyDecision, error)
}

// Signer produces SSH certificates from a CertSpec and provided serial.
// Implementations live in internal/adapters (e.g., signer/disk, signer/akv, signer/vault).
// If we later support third-party plugins, we'll expose a public contract under pkg/plugin/*
// and add a small bridge adapter to satisfy this port without changing use cases.
type Signer interface {
	// Sign issues a certificate using CA key material, assigning the provided serial, and returns
	// the raw OpenSSH certificate bytes plus the signing key fingerprint.
	Sign(spec domain.CertSpec, serial uint64) (cert []byte, keyFP string, err error)
}

// Authenticator verifies client credentials (e.g., OIDC bearer) and yields a normalized Identity.
// Implementations live in adapters (e.g., go-oidc based).
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (domain.Identity, error)
}

// SerialStore provides monotonically increasing certificate serial numbers.
// Implementations may be in-memory for dev, sqlite/postgres for prod.
type SerialStore interface {
	Next(ctx context.Context) (uint64, error)
}

// AuditSink persists or emits audit events (stdout, db, log aggregator).
type AuditSink interface {
	Write(ctx context.Context, ev domain.AuditEvent) error
}

// AgentLoader loads a keypair + certificate into an SSH agent for a bounded lifetime (CLI-side).
// Implementations live in adapters and should avoid persisting secrets unless explicitly requested.
type AgentLoader interface {
	Load(ctx context.Context, privateKeyPEM []byte, cert []byte, lifetime time.Duration, comment string) error
}
