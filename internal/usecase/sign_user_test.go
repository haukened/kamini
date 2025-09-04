package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/haukened/kamini/internal/domain"
)

type fakeClock struct{ t time.Time }

func (f fakeClock) Now() time.Time { return f.t }

type fakeAuth struct {
	id  domain.Identity
	err error
}

func (f fakeAuth) Authenticate(ctx context.Context, bearer string) (domain.Identity, error) {
	return f.id, f.err
}

type fakeAuthz struct {
	dec domain.PolicyDecision
	err error
}

func (f fakeAuthz) Decide(id domain.Identity, ctx domain.SignContext) (domain.PolicyDecision, error) {
	return f.dec, f.err
}

type fakeSeq struct {
	v   uint64
	err error
}

func (f *fakeSeq) Next(ctx context.Context) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.v++
	return f.v, nil
}

type fakeSigner struct {
	cert []byte
	fp   string
	err  error
}

func (f fakeSigner) Sign(spec domain.CertSpec, serial uint64) ([]byte, string, error) {
	return f.cert, f.fp, f.err
}

type sink struct{ last domain.AuditEvent }

func (s *sink) Write(ctx context.Context, ev domain.AuditEvent) error { s.last = ev; return nil }

type nolog struct{}

func (nolog) Debug(context.Context, string, ...any) {}
func (nolog) Info(context.Context, string, ...any)  {}
func (nolog) Warn(context.Context, string, ...any)  {}
func (nolog) Error(context.Context, string, ...any) {}
func (nolog) With(...any) Logger                    { return nolog{} }
func (nolog) WithGroup(string) Logger               { return nolog{} }

func TestSignUser_Success(t *testing.T) {
	fc := fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	a := fakeAuth{id: domain.Identity{Subject: "sub", Username: "alice"}}
	az := fakeAuthz{dec: domain.PolicyDecision{Principals: []string{"alice"}, TTL: time.Hour}}
	seq := &fakeSeq{}
	signer := fakeSigner{cert: []byte("ssh-ed25519-cert-v01@openssh.com AAAA"), fp: "SHA256:xyz"}
	aud := &sink{}
	svc := NewSignUserService(SignUserService{
		Log:    nolog{},
		Auth:   a,
		Authz:  az,
		Seq:    seq,
		Signer: signer,
		Audit:  aud,
		Clock:  fc,
		TTL:    domain.TTL{Default: time.Hour, Max: 4 * time.Hour},
	})
	out, err := svc.Execute(context.Background(), SignUserInput{
		Bearer:              "token",
		PublicKeyAuthorized: "ssh-ed25519 AAAA",
		RequestedTTL:        time.Hour,
		SourceIP:            "1.2.3.4",
		TraceID:             "trace",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Serial == 0 || len(out.Certificate) == 0 {
		t.Fatalf("bad output: %+v", out)
	}
	if out.NotBefore.After(out.NotAfter) {
		t.Fatalf("invalid window")
	}
	if len(out.Principals) != 1 || out.Principals[0] != "alice" {
		t.Fatalf("principals=%v", out.Principals)
	}
	if !aud.last.Success() || aud.last.Stage != domain.StageSign {
		t.Fatalf("expected success sign-stage audit: %+v", aud.last)
	}
	if aud.last.Serial == nil || *aud.last.Serial != out.Serial {
		t.Fatalf("expected serial in audit event")
	}
	if aud.last.Attrs == nil || aud.last.Attrs["key_id"] == "" || aud.last.Attrs["ca_fp"] != "SHA256:xyz" {
		t.Fatalf("expected audit attrs with key_id and ca_fp, got: %+v", aud.last.Attrs)
	}
}

func TestSignUser_MissingBearer(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{Log: nolog{}, Audit: aud, Clock: fakeClock{t: time.Now().UTC()}, TTL: domain.TTL{Default: time.Hour, Max: 2 * time.Hour}})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if aud.last.Stage != domain.StageAuthn || aud.last.Success() || aud.last.ErrorCode == "" {
		t.Fatalf("expected AUTHN failure audit with error code, got: %+v", aud.last)
	}
}

func TestSignUser_MissingPublicKey(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{Log: nolog{}, Audit: aud, Clock: fakeClock{t: time.Now().UTC()}, TTL: domain.TTL{Default: time.Hour, Max: 2 * time.Hour}})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "token", PublicKeyAuthorized: ""})
	if !errors.Is(err, domain.ErrMissingPublicKey) {
		t.Fatalf("expected ErrMissingPublicKey, got %v", err)
	}
	if aud.last.Stage != domain.StageInput || aud.last.ErrorCode != domain.CodeMissingPublicKey || aud.last.Success() {
		t.Fatalf("expected INPUT failure with CodeMissingPublicKey, got: %+v", aud.last)
	}
}

func TestSignUser_AuthnFail(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{Log: nolog{}, Auth: fakeAuth{err: errors.New("bad token")}, Audit: aud, Clock: fakeClock{t: time.Now().UTC()}, TTL: domain.TTL{Default: time.Hour, Max: 2 * time.Hour}})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "token", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil {
		t.Fatalf("expected authn error")
	}
	if aud.last.Stage != domain.StageAuthn || aud.last.Success() {
		t.Fatalf("expected AUTHN failure audit, got: %+v", aud.last)
	}
}

func TestSignUser_AuthzDeny(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{
		Log:   nolog{},
		Auth:  fakeAuth{id: domain.Identity{Subject: "s"}},
		Authz: fakeAuthz{err: domain.PolicyDeny{Code: domain.DenyDefault}},
		Audit: aud,
		Clock: fakeClock{t: time.Now().UTC()},
		TTL:   domain.TTL{Default: time.Hour, Max: 2 * time.Hour},
	})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "t", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil {
		t.Fatalf("expected deny error")
	}
	if aud.last.Stage != domain.StageAuthz || aud.last.ErrorCode != domain.CodePolicyDenied || aud.last.Success() {
		t.Fatalf("expected AUTHZ failure policy denied audit, got: %+v", aud.last)
	}
}

func TestSignUser_SerialFail(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{
		Log:   nolog{},
		Auth:  fakeAuth{id: domain.Identity{Subject: "s"}},
		Authz: fakeAuthz{dec: domain.PolicyDecision{Principals: []string{"alice"}, TTL: time.Hour}},
		Seq:   &fakeSeq{err: errors.New("db down")},
		Audit: aud,
		Clock: fakeClock{t: time.Now().UTC()},
		TTL:   domain.TTL{Default: time.Hour, Max: 2 * time.Hour},
	})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "t", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if aud.last.Stage != domain.StagePolicy || aud.last.Success() || aud.last.ErrorCode == "" {
		t.Fatalf("expected POLICY failure audit with error code, got: %+v", aud.last)
	}
}

func TestSignUser_SignerFail(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{
		Log:    nolog{},
		Auth:   fakeAuth{id: domain.Identity{Subject: "s"}},
		Authz:  fakeAuthz{dec: domain.PolicyDecision{Principals: []string{"alice"}, TTL: time.Hour}},
		Seq:    &fakeSeq{},
		Signer: fakeSigner{err: errors.New("sign fail")},
		Audit:  aud,
		Clock:  fakeClock{t: time.Now().UTC()},
		TTL:    domain.TTL{Default: time.Hour, Max: 2 * time.Hour},
	})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "t", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if aud.last.Stage != domain.StageSign || aud.last.Success() || aud.last.ErrorCode == "" {
		t.Fatalf("expected SIGN failure audit with error code, got: %+v", aud.last)
	}
}

func TestSignUser_BuildCertSpecNoPrincipals(t *testing.T) {
	aud := &sink{}
	svc := NewSignUserService(SignUserService{
		Log:   nolog{},
		Auth:  fakeAuth{id: domain.Identity{Subject: "s"}},
		Authz: fakeAuthz{dec: domain.PolicyDecision{Principals: nil, TTL: time.Hour}},
		Seq:   &fakeSeq{},
		// signer won't be reached
		Signer: fakeSigner{cert: []byte("unused"), fp: "unused"},
		Audit:  aud,
		Clock:  fakeClock{t: time.Now().UTC()},
		TTL:    domain.TTL{Default: time.Hour, Max: 2 * time.Hour},
	})
	_, err := svc.Execute(context.Background(), SignUserInput{Bearer: "t", PublicKeyAuthorized: "ssh-ed25519 AAAA"})
	if err == nil || !errors.Is(err, domain.ErrNoPrincipals) {
		t.Fatalf("expected ErrNoPrincipals, got %v", err)
	}
	if aud.last.Stage != domain.StagePolicy || aud.last.ErrorCode != domain.CodeNoPrincipals {
		t.Fatalf("expected POLICY failure with CodeNoPrincipals, got: %+v", aud.last)
	}
}
func TestSignUserService_String(t *testing.T) {
	ttl := domain.TTL{Default: time.Hour, Max: 4 * time.Hour}
	svc := SignUserService{TTL: ttl}
	got := svc.String()
	want := "signuser ttl=1h0m0s/4h0m0s"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	ttl = domain.TTL{Default: 0, Max: 0}
	svc = SignUserService{TTL: ttl}
	got = svc.String()
	want = "signuser ttl=0s/0s"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
