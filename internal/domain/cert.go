package domain

import "time"

// CertSpec is the *request-to-sign* (what the usecase wants the signer to produce).
type CertSpec struct {
	PublicKeyAuthorized string            // "ssh-ed25519 AAAA..."
	KeyID               string            // stable audit identifier (e.g., sub|username|serial)
	Principals          []string          // login names approved by policy
	ValidAfter          time.Time         // usually now-30s
	ValidBefore         time.Time         // now + ttl (clamped)
	CriticalOptions     map[string]string // e.g., source-address
	Extensions          map[string]string // e.g., permit-pty
}

// Validate ensures a well-formed spec (domain-level checks only).
func (c CertSpec) Validate(now time.Time) error {
	if c.PublicKeyAuthorized == "" {
		return ErrMissingPublicKey
	}
	if len(c.Principals) == 0 {
		return ErrNoPrincipals
	}
	if !c.ValidBefore.After(c.ValidAfter) {
		return ErrInvalidValidity
	}
	// length/charset of principals were already normalized earlier.
	return nil
}

// CertRecord is what we *record* post-signing (for audit, not the raw cert bytes).
type CertRecord struct {
	Serial      uint64
	KeyID       string
	Subject     string
	Principals  []string
	NotBefore   time.Time
	NotAfter    time.Time
	KeyFP       string // key fingerprint (computed by adapter, stored here)
	PluginAuth  string // which authenticator plugin decided identity
	PluginAuthz string // which authorizer plugin decided policy
	RequestIP   string
}

// SignRequest is the normalized request to sign a certificate from a client.
// It represents the client's intent prior to policy evaluation.
type SignRequest struct {
	PublicKeyAuthorized string
	RequestedPrincipals []string
	RequestedTTL        time.Duration
	SourceIP            string
	TraceID             string
}

// Signer is the shape for certificate signing ports.
type Signer interface {
	// Sign produces a certificate and returns the assigned serial and key fingerprint.
	// The implementation lives in adapters; the shape remains in domain for tests.
	Sign(spec CertSpec) (serial uint64, keyFP string, err error)
}

// BuildCertSpec composes a CertSpec from policy and identity using clock and TTL rules.
// ValidAfter = now - DefaultSkew
// ValidBefore = ValidAfter + ttl.Clamp(policyTTL)
func BuildCertSpec(id Identity, decision PolicyDecision, ttl TTL, clk Clock, keyID string) (CertSpec, error) {
	now := clk.Now()
	nb := now.Add(-DefaultSkew)
	dur := ttl.Clamp(decision.TTL)
	na := nb.Add(dur)
	spec := CertSpec{
		PublicKeyAuthorized: "",
		KeyID:               keyID,
		Principals:          NormalizePrincipals(decision.Principals),
		ValidAfter:          nb,
		ValidBefore:         na,
		CriticalOptions:     cloneStringMap(decision.CriticalOptions),
		Extensions:          cloneStringMap(decision.Extensions),
	}
	return spec, nil
}
