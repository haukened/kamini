package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	ilog "github.com/haukened/kamini/internal/log"
)

// helper to spin up a minimal OIDC discovery + JWKS server for tests
func newOIDCTestServer(t *testing.T, pubJWK any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	issuer := srv.URL
	jwks := map[string]any{"keys": []any{pubJWK}}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	return srv
}

func rsaToJWK(pub *rsa.PublicKey, kid string) map[string]any {
	// base64url (no padding)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigEndianBytes(pub.E))
	return map[string]any{
		"kty": "RSA",
		"n":   n,
		"e":   e,
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
	}
}

func bigEndianBytes(i int) []byte {
	// minimal bytes for exponent (usually 65537 -> 0x01 0x00 0x01)
	if i <= 0xFF {
		return []byte{byte(i)}
	}
	if i <= 0xFFFF {
		return []byte{byte(i >> 8), byte(i)}
	}
	return []byte{byte(i >> 16), byte(i >> 8), byte(i)}
}

func signJWT(t *testing.T, priv *rsa.PrivateKey, kid, iss, aud, sub string, claims map[string]any, ttl time.Duration) string {
	t.Helper()
	now := time.Now().UTC()
	std := jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	for k, v := range claims {
		std[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, std)
	token.Header["kid"] = kid
	s, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestOIDCAuthenticator_Authenticate_Valid(t *testing.T) {
	// generate keypair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid := kidFromKey(&priv.PublicKey)
	srv := newOIDCTestServer(t, rsaToJWK(&priv.PublicKey, kid))
	defer srv.Close()

	cfg := OIDCAuthConfig{IssuerURL: srv.URL, ClientID: "test-client"}
	a, err := NewOIDCAuthenticator(context.Background(), cfg, ilog.NewNop())
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}

	token := signJWT(t, priv, kid, srv.URL, cfg.ClientID, "sub-123", map[string]any{
		"preferred_username": "Alice",
		"email":              "alice@example.com",
		"roles":              []string{"dev"},
		"groups":             []string{"eng"},
		"email_verified":     true,
	}, time.Hour)

	id, err := a.Authenticate(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "sub-123" {
		t.Fatalf("subject=%q", id.Subject)
	}
	if id.Username != "alice" {
		t.Fatalf("username=%q", id.Username)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("email=%q", id.Email)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "dev" {
		t.Fatalf("roles=%v", id.Roles)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "eng" {
		t.Fatalf("groups=%v", id.Groups)
	}
}

func TestOIDCAuthenticator_AudienceRequired(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid := kidFromKey(&priv.PublicKey)
	srv := newOIDCTestServer(t, rsaToJWK(&priv.PublicKey, kid))
	defer srv.Close()

	cfg := OIDCAuthConfig{IssuerURL: srv.URL, ClientID: "right-client"}
	a, err := NewOIDCAuthenticator(context.Background(), cfg, ilog.NewNop())
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}

	// wrong audience
	token := signJWT(t, priv, kid, srv.URL, "wrong-client", "sub-123", nil, time.Hour)
	if _, err := a.Authenticate(context.Background(), token); err == nil {
		t.Fatalf("expected audience error")
	}
}

func kidFromKey(pub *rsa.PublicKey) string {
	// simple kid: sha256 of modulus bytes (truncated)
	sum := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}
