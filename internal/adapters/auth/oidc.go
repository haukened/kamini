package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	oidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

// OIDCAuthConfig controls OIDC authenticator behavior.
type OIDCAuthConfig struct {
	IssuerURL         string
	ClientID          string
	SkipClientIDCheck bool

	UsernameClaim string // default: "preferred_username"
	EmailClaim    string // default: "email"
	RolesClaim    string // default: "roles"
	GroupsClaim   string // default: "groups"

	HTTPClient *http.Client // optional; if nil, default client is used
}

// OIDCAuthenticator verifies ID tokens and maps claims to a domain.Identity.
type OIDCAuthenticator struct {
	verifier      *oidc.IDTokenVerifier
	usernameClaim string
	emailClaim    string
	rolesClaim    string
	groupsClaim   string
	L             usecase.Logger
}

// assert interfaces
var _ usecase.Authenticator = (*OIDCAuthenticator)(nil)

// NewOIDCAuthenticator constructs an OIDC authenticator backed by discovery metadata.
func NewOIDCAuthenticator(ctx context.Context, cfg OIDCAuthConfig, l usecase.Logger) (*OIDCAuthenticator, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("issuer URL required")
	}
	if cfg.ClientID == "" && !cfg.SkipClientIDCheck {
		return nil, errors.New("clientID required unless SkipClientIDCheck is true")
	}
	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	v := provider.Verifier(&oidc.Config{
		ClientID:          cfg.ClientID,
		SkipClientIDCheck: cfg.SkipClientIDCheck,
		// ClockSkew and time are derived from context; default tolerance is small.
	})
	a := &OIDCAuthenticator{
		verifier:      v,
		usernameClaim: firstNonEmpty(cfg.UsernameClaim, "preferred_username"),
		emailClaim:    firstNonEmpty(cfg.EmailClaim, "email"),
		rolesClaim:    firstNonEmpty(cfg.RolesClaim, "roles"),
		groupsClaim:   firstNonEmpty(cfg.GroupsClaim, "groups"),
		L:             l,
	}
	return a, nil
}

// Authenticate verifies the bearer token (ID token) and returns a normalized Identity.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, bearer string) (domain.Identity, error) {
	token := strings.TrimSpace(bearer)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return domain.Identity{}, errors.New("empty bearer token")
	}
	idt, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return domain.Identity{}, err
	}
	// Extract raw claims into a generic map for mapping.
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return domain.Identity{}, err
	}

	sub := idt.Subject
	email := getString(claims, a.emailClaim)
	username := getString(claims, a.usernameClaim)
	if username == "" && email != "" {
		if i := strings.IndexByte(email, '@'); i > 0 {
			username = email[:i]
		}
	}
	if username == "" {
		username = sub
	}
	roles := getStringSlice(claims, a.rolesClaim)
	groups := getStringSlice(claims, a.groupsClaim)

	// Keep only a small set of extra claims to avoid carting the whole token.
	extras := map[string]any{
		"iss":            idt.Issuer,
		"aud":            idt.Audience,
		"email_verified": getBool(claims, "email_verified"),
	}

	id := domain.Identity{
		Subject:  sub,
		Username: strings.ToLower(username),
		Email:    strings.ToLower(email),
		Roles:    roles,
		Groups:   groups,
		Claims:   extras,
	}
	if a.L != nil {
		a.L.Debug(ctx, "oidc authenticated", "sub", id.Subject, "username", id.Username)
	}
	return id, nil
}

func firstNonEmpty(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		}
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case bool:
			return t
		}
	}
	return false
}

func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch s := v.(type) {
	case []any:
		out := make([]string, 0, len(s))
		for _, it := range s {
			if str, ok := it.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case []string:
		return append([]string(nil), s...)
	default:
		return nil
	}
}
