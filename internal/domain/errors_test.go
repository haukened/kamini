package domain

import (
	"errors"
	"testing"
)

func TestDomainErrors(t *testing.T) {
	if ErrMissingPublicKey == nil || ErrNoPrincipals == nil || ErrInvalidValidity == nil || ErrPolicyDenied == nil {
		t.Fatalf("domain error variables must be non-nil")
	}
	// Sanity check errors.Is behavior
	if !errors.Is(ErrMissingPublicKey, ErrMissingPublicKey) {
		t.Fatalf("errors.Is should match the same var")
	}
}
