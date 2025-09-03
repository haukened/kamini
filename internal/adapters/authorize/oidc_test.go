package authorize

import (
	"testing"
	"time"

	"github.com/haukened/kamini/internal/domain"
)

func TestOIDCAuthorizer_AllowByRole(t *testing.T) {
	a := NewOIDCAuthorizer(OIDCAuthorizerConfig{
		AllowRoles: []string{"dev"},
		Principals: []string{"{username}", "{emailLocal}"},
		DefaultTTL: time.Hour,
		MaxTTL:     4 * time.Hour,
	})
	id := domain.Identity{Subject: "s", Username: "alice", Email: "alice@example.com", Roles: []string{"dev"}}
	dec, err := a.Decide(id, domain.SignContext{RequestedTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if len(dec.Principals) == 0 || dec.Principals[0] != "alice" {
		t.Fatalf("principals=%v", dec.Principals)
	}
	if dec.TTL != 2*time.Hour {
		t.Fatalf("ttl=%s", dec.TTL)
	}
}

func TestOIDCAuthorizer_DenyWhenNoMatch(t *testing.T) {
	a := NewOIDCAuthorizer(OIDCAuthorizerConfig{AllowRoles: []string{"ops"}})
	id := domain.Identity{Subject: "s", Username: "alice", Roles: []string{"dev"}}
	if _, err := a.Decide(id, domain.SignContext{}); err == nil {
		t.Fatalf("expected deny")
	}
}

func TestOIDCAuthorizer_PrincipalTemplateFallback(t *testing.T) {
	a := NewOIDCAuthorizer(OIDCAuthorizerConfig{AllowGroups: []string{"eng"}})
	id := domain.Identity{Subject: "s", Username: "", Email: "user@example.com", Groups: []string{"eng"}}
	dec, err := a.Decide(id, domain.SignContext{})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if len(dec.Principals) == 0 || dec.Principals[0] == "" {
		t.Fatalf("principals=%v", dec.Principals)
	}
}

func TestOIDCAuthorizer_TTLClampToMax(t *testing.T) {
	a := NewOIDCAuthorizer(OIDCAuthorizerConfig{
		AllowRoles: []string{"dev"},
		DefaultTTL: time.Hour,
		MaxTTL:     2 * time.Hour,
	})
	id := domain.Identity{Subject: "s", Username: "alice", Roles: []string{"dev"}}
	dec, err := a.Decide(id, domain.SignContext{RequestedTTL: 10 * time.Hour})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.TTL != 2*time.Hour {
		t.Fatalf("ttl=%s want=%s", dec.TTL, 2*time.Hour)
	}
}

func TestOIDCAuthorizer_TTLDefaultWhenZero(t *testing.T) {
	a := NewOIDCAuthorizer(OIDCAuthorizerConfig{
		AllowGroups: []string{"eng"},
		DefaultTTL:  30 * time.Minute,
		MaxTTL:      3 * time.Hour,
	})
	id := domain.Identity{Subject: "s", Username: "bob", Groups: []string{"eng"}}
	dec, err := a.Decide(id, domain.SignContext{RequestedTTL: 0})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.TTL != 30*time.Minute {
		t.Fatalf("ttl=%s want=%s", dec.TTL, 30*time.Minute)
	}
}
