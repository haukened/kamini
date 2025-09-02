package domain

import (
	"testing"
	"time"
)

func TestCertSpecValidate(t *testing.T) {
	now := time.Now().UTC()
	spec := CertSpec{
		PublicKeyAuthorized: "ssh-ed25519 AAAA",
		Principals:          []string{"alice"},
		ValidAfter:          now,
		ValidBefore:         now.Add(time.Hour),
	}
	if err := spec.Validate(now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spec2 := spec
	spec2.PublicKeyAuthorized = ""
	if err := spec2.Validate(now); err != ErrMissingPublicKey {
		t.Fatalf("want ErrMissingPublicKey got %v", err)
	}

	spec3 := spec
	spec3.Principals = nil
	if err := spec3.Validate(now); err != ErrNoPrincipals {
		t.Fatalf("want ErrNoPrincipals got %v", err)
	}

	spec4 := spec
	spec4.ValidBefore = spec4.ValidAfter
	if err := spec4.Validate(now); err != ErrInvalidValidity {
		t.Fatalf("want ErrInvalidValidity got %v", err)
	}
}

type fakeClock struct{ t time.Time }

func (f fakeClock) Now() time.Time { return f.t }

func TestBuildCertSpec(t *testing.T) {
	fc := fakeClock{t: time.Date(2024, 3, 10, 12, 0, 0, 0, time.UTC)}
	dec := PolicyDecision{
		Principals:      []string{"Alice", "alice"},
		TTL:             time.Hour,
		CriticalOptions: map[string]string{"source-address": "1.2.3.4/32"},
		Extensions:      map[string]string{"permit-pty": ""},
	}
	spec, err := BuildCertSpec(Identity{}, dec, TTL{Default: time.Hour, Max: 4 * time.Hour}, fc, "kid")
	if err != nil {
		t.Fatalf("BuildCertSpec error: %v", err)
	}
	if got, want := spec.ValidAfter, fc.t.Add(-DefaultSkew); !got.Equal(want) {
		t.Fatalf("ValidAfter = %v, want %v", got, want)
	}
	if got, want := spec.ValidBefore.Sub(spec.ValidAfter), time.Hour; got != want {
		t.Fatalf("duration = %v, want %v", got, want)
	}
	if len(spec.Principals) != 1 || spec.Principals[0] != "alice" {
		t.Fatalf("principals = %v", spec.Principals)
	}
	if spec.KeyID != "kid" {
		t.Fatalf("KeyID = %q", spec.KeyID)
	}
}
