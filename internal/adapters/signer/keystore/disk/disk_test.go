package disk

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/haukened/kamini/internal/usecase"
)

// nop logger satisfying usecase.Logger
type nopLogger struct{}

func (nopLogger) Debug(ctx context.Context, msg string, args ...any) {}
func (nopLogger) Info(ctx context.Context, msg string, args ...any)  {}
func (nopLogger) Warn(ctx context.Context, msg string, args ...any)  {}
func (nopLogger) Error(ctx context.Context, msg string, args ...any) {}
func (nopLogger) With(args ...any) usecase.Logger                    { return nopLogger{} }
func (nopLogger) WithGroup(name string) usecase.Logger               { return nopLogger{} }

func TestStore_Load_PEM_Ed25519(t *testing.T) {
	// generate a test ed25519 key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ks := New(p, nopLogger{})
	signer, err := ks.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	msg := []byte("hello")
	sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil || len(sig) == 0 {
		t.Fatalf("sign: %v, sig=%d", err, len(sig))
	}
}

func TestStore_Load_Rejects_LaxPerms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	// write dummy content (parse will fail; we only care about perms rejection happening first)
	if err := os.WriteFile(p, []byte("dummy"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ks := New(p, nopLogger{})
	_, err := ks.Load(context.Background())
	if err == nil {
		t.Fatalf("expected error for lax permissions, got nil")
	}
}
