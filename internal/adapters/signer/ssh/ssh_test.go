package ssh

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	sshx "golang.org/x/crypto/ssh"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

type fakeKeySource struct{ key crypto.Signer }

func (f fakeKeySource) Load(ctx context.Context) (crypto.Signer, error) { return f.key, nil }

type nopLogger struct{}

func (nopLogger) Debug(ctx context.Context, msg string, args ...any) {}
func (nopLogger) Info(ctx context.Context, msg string, args ...any)  {}
func (nopLogger) Warn(ctx context.Context, msg string, args ...any)  {}
func (nopLogger) Error(ctx context.Context, msg string, args ...any) {}
func (nopLogger) With(args ...any) usecase.Logger                    { return nopLogger{} }
func (nopLogger) WithGroup(name string) usecase.Logger               { return nopLogger{} }

func TestOpenSSHSigner_Sign(t *testing.T) {
	// Generate a user key to be certified.
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := sshx.NewPublicKey(userPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	authLine := string(sshx.MarshalAuthorizedKey(userPub))

	// Generate a CA key for signing.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s := NewOpenSSHSigner(fakeKeySource{key: caPriv}, nopLogger{})

	spec := domain.CertSpec{
		PublicKeyAuthorized: authLine,
		KeyID:               "kid",
		Principals:          []string{"alice"},
		ValidAfter:          time.Now().Add(-time.Minute),
		ValidBefore:         time.Now().Add(time.Hour),
		CriticalOptions:     map[string]string{"source-address": "10.0.0.0/8"},
		Extensions:          map[string]string{"permit-pty": ""},
	}
	cert, fp, err := s.Sign(spec, 42)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(cert) == 0 {
		t.Fatalf("empty cert bytes")
	}
	if fp == "" {
		t.Fatalf("empty fingerprint")
	}

	// Parse the cert and verify key id and serial.
	pk, err := sshx.ParsePublicKey(cert)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	c, ok := pk.(*sshx.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", pk)
	}
	if c.KeyId != "kid" || c.Serial != 42 {
		t.Fatalf("unexpected fields: keyid=%s serial=%d", c.KeyId, c.Serial)
	}
}
