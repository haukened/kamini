// Package signer defines the public plugin contract for certificate signers.
//
// Implementations should encapsulate CA private key management (disk, KMS, etc.)
// and expose a uniform signing API. The server bridges between internal domain
// types and these plugin types in adapters.
package signer

import (
	"context"
	"time"
)

// CertSpec is the public signing request shape for plugins, mirroring core fields
// without importing internal packages.
type CertSpec struct {
	PublicKeyAuthorized string            // "ssh-ed25519 AAAA..."
	KeyID               string            // stable audit identifier
	Principals          []string          // login names approved by policy
	ValidAfter          time.Time         // UTC
	ValidBefore         time.Time         // UTC
	CriticalOptions     map[string]string // e.g., source-address
	Extensions          map[string]string // e.g., permit-pty
}

// Result contains minimal outputs from a signing operation.
type Result struct {
	Serial      uint64
	Fingerprint string // CA-signed cert fingerprint (or signing key fp)
}

// Signer is the plugin interface for signing SSH user certificates.
// Implementations must be safe for concurrent use.
type Signer interface {
	// Sign issues a certificate using the provider's CA key material.
	Sign(ctx context.Context, spec CertSpec) (Result, error)

	// Close releases any resources (e.g., KMS clients). Implementations may no-op.
	Close() error
}

// Configurable is optional. Implement if you require configuration before use.
type Configurable interface {
	Configure(ctx context.Context, config map[string]any) error
}

// Identifiable is optional. Implement to expose a stable name for logging/metrics.
type Identifiable interface {
	Name() string
}
