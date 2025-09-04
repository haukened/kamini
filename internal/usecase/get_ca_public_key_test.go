package usecase

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

type fakeCAKeySource struct{ s crypto.Signer }

func (f fakeCAKeySource) Load(ctx context.Context) (crypto.Signer, error) { return f.s, nil }

type nopLog struct{}

func (nopLog) Debug(context.Context, string, ...any) {}
func (nopLog) Info(context.Context, string, ...any)  {}
func (nopLog) Warn(context.Context, string, ...any)  {}
func (nopLog) Error(context.Context, string, ...any) {}
func (nopLog) With(...any) Logger                    { return nopLog{} }
func (nopLog) WithGroup(string) Logger               { return nopLog{} }

func TestGetCAPublicKeyService(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewGetCAPublicKeyService(fakeCAKeySource{priv}, nopLog{})
	out, err := svc.Execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.PublicKey == nil {
		t.Fatalf("nil public key")
	}
}

type errKeySource struct{ e error }

func (e errKeySource) Load(ctx context.Context) (crypto.Signer, error) { return nil, e.e }

type nilKeySource struct{}

func (nilKeySource) Load(ctx context.Context) (crypto.Signer, error) { return nil, nil }

func TestGetCAPublicKeyService_LoadError(t *testing.T) {
	svc := NewGetCAPublicKeyService(errKeySource{e: errors.New("load fail")}, nopLog{})
	_, err := svc.Execute(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestGetCAPublicKeyService_NilSigner(t *testing.T) {
	svc := NewGetCAPublicKeyService(nilKeySource{}, nopLog{})
	_, err := svc.Execute(context.Background())
	if err == nil {
		t.Fatalf("expected error for nil signer")
	}
}
