package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/haukened/kamini/internal/domain"
)

// SignUserInput carries the normalized inputs for issuing a user certificate.
type SignUserInput struct {
	Bearer              string
	PublicKeyAuthorized string
	RequestedTTL        time.Duration
	SourceIP            string
	TraceID             string
}

// SignUserOutput is the normalized result of a successful issuance.
type SignUserOutput struct {
	Serial        uint64
	Certificate   []byte
	NotBefore     time.Time
	NotAfter      time.Time
	Principals    []string
	KeyID         string
	CAFingerprint string // for logs/audit; adapters may ignore
}

// SignUserService orchestrates AuthN -> AuthZ -> Serial -> Spec -> Sign -> Audit.
type SignUserService struct {
	Log    Logger
	Auth   Authenticator
	Authz  Authorizer
	Seq    SerialStore
	Signer Signer
	Audit  AuditSink
	Clock  Clock
	TTL    domain.TTL // policy TTL (default, max)
}

func NewSignUserService(deps SignUserService) *SignUserService { return &deps }

// Execute performs the end-to-end flow to issue a user certificate.
func (svc *SignUserService) Execute(ctx context.Context, in SignUserInput) (SignUserOutput, error) {
	now := svc.Clock.Now()
	signCtx := domain.SignContext{
		RequestedTTL: in.RequestedTTL,
		SourceIP:     in.SourceIP,
		Now:          now,
		TraceID:      in.TraceID,
	}

	// Basic input validation
	if in.Bearer == "" {
		err := errors.New("missing bearer")
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StageAuthn, domain.Identity{}, nil, signCtx, err, nil))
		return SignUserOutput{}, err
	}
	if in.PublicKeyAuthorized == "" {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StageInput, domain.Identity{}, nil, signCtx, domain.ErrMissingPublicKey, nil))
		return SignUserOutput{}, domain.ErrMissingPublicKey
	}

	// 1) Authenticate
	id, err := svc.Auth.Authenticate(ctx, in.Bearer)
	if err != nil {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StageAuthn, domain.Identity{}, nil, signCtx, err, nil))
		return SignUserOutput{}, err
	}

	// 2) Authorize / policy decision
	dec, err := svc.Authz.Decide(id, signCtx)
	if err != nil {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StageAuthz, id, nil, signCtx, err, nil))
		return SignUserOutput{}, err
	}

	// 3) Serial
	serial, err := svc.Seq.Next(ctx)
	if err != nil {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StagePolicy, id, dec.Principals, signCtx, err, nil))
		return SignUserOutput{}, err
	}

	// 4) Build cert spec with TTL clamp and key ID
	keyID := domain.ComposeKeyID(id, serial)
	spec, err := domain.BuildCertSpec(id, dec, svc.TTL, svc.Clock, keyID)
	if err != nil {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StagePolicy, id, dec.Principals, signCtx, err, nil))
		return SignUserOutput{}, err
	}
	spec.PublicKeyAuthorized = in.PublicKeyAuthorized

	// 5) Sign
	cert, fp, err := svc.Signer.Sign(spec, serial)
	if err != nil {
		_ = svc.Audit.Write(ctx, domain.NewAuditFailure(domain.ActionIssueUserCert, domain.StageSign, id, dec.Principals, signCtx, err, nil))
		return SignUserOutput{}, err
	}

	// 6) Audit success
	_ = svc.Audit.Write(ctx, domain.NewAuditSuccess(domain.ActionIssueUserCert, id, dec.Principals, serial, spec.ValidAfter, spec.ValidBefore, signCtx, map[string]string{
		"ca_fp":  fp,
		"key_id": keyID,
	}))

	if svc.Log != nil {
		svc.Log.Info(ctx, "issued user cert", "serial", serial, "principals", dec.Principals, "nb", spec.ValidAfter, "na", spec.ValidBefore)
	}

	return SignUserOutput{
		Serial:        serial,
		Certificate:   cert,
		NotBefore:     spec.ValidAfter,
		NotAfter:      spec.ValidBefore,
		Principals:    dec.Principals,
		KeyID:         keyID,
		CAFingerprint: fp,
	}, nil
}

// String returns a concise description useful in logs.
func (svc SignUserService) String() string {
	return fmt.Sprintf("signuser ttl=%s/%s", svc.TTL.Default, svc.TTL.Max)
}
