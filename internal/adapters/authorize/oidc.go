package authorize

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/haukened/kamini/internal/domain"
	"github.com/haukened/kamini/internal/usecase"
)

// OIDCAuthorizerConfig contains simple allow rules and defaults.
type OIDCAuthorizerConfig struct {
	// Any of these roles/groups grants access. If both slices are empty, deny by default.
	AllowRoles  []string
	AllowGroups []string

	// Principal templates; default uses normalized username.
	// Template supports placeholders: {username}, {emailLocal}.
	Principals []string

	// TTL bounds.
	DefaultTTL time.Duration
	MaxTTL     time.Duration

	// Optional IP CIDRs (source-address critical option) when set.
	SourceCIDRs []string // e.g., ["10.0.0.0/8", "192.168.0.0/16"]
}

// OIDCAuthorizer implements a simple role/group based authorization.
type OIDCAuthorizer struct {
	cfg OIDCAuthorizerConfig
}

// assert interfaces
var _ usecase.Authorizer = (*OIDCAuthorizer)(nil)

func NewOIDCAuthorizer(cfg OIDCAuthorizerConfig) *OIDCAuthorizer {
	return &OIDCAuthorizer{cfg: cfg}
}

// Decide returns a PolicyDecision or a PolicyDeny.
func (a *OIDCAuthorizer) Decide(id domain.Identity, ctx domain.SignContext) (domain.PolicyDecision, error) {
	if !a.allowed(id) {
		return domain.PolicyDecision{}, domain.PolicyDeny{Code: domain.DenyDefault, Message: "access denied"}
	}

	principals := domain.NormalizePrincipals(a.buildPrincipals(id))
	if len(principals) == 0 {
		return domain.PolicyDecision{}, domain.PolicyDeny{Code: domain.DenyPrincipalNotAllowed, Message: "no principals"}
	}

	// TTL clamp via domain.TTL rules happens later; we set the requested TTL here.
	ttl := a.cfg.DefaultTTL
	if ctx.RequestedTTL > 0 {
		ttl = ctx.RequestedTTL
	}

	opts := map[string]string{}
	if len(a.cfg.SourceCIDRs) > 0 {
		// Optionally constrain cert usage by client IPs; use best-effort normalization
		var cidrs []string
		for _, c := range a.cfg.SourceCIDRs {
			cidrs = append(cidrs, strings.TrimSpace(c))
		}
		if ip, _ := netip.ParseAddr(ctx.SourceIP); ip.IsValid() {
			// You can tighten logic to include the specific requester IP as well.
		}
		opts["source-address"] = strings.Join(cidrs, ",")
	}

	return domain.PolicyDecision{
		Principals:      principals,
		TTL:             ttl,
		CriticalOptions: opts,
		Extensions:      map[string]string{"permit-pty": ""},
	}, nil
}

func (a *OIDCAuthorizer) allowed(id domain.Identity) bool {
	if len(a.cfg.AllowRoles) == 0 && len(a.cfg.AllowGroups) == 0 {
		return false
	}
	if intersectsFold(a.cfg.AllowRoles, id.Roles) {
		return true
	}
	if intersectsFold(a.cfg.AllowGroups, id.Groups) {
		return true
	}
	return false
}

func (a *OIDCAuthorizer) buildPrincipals(id domain.Identity) []string {
	if len(a.cfg.Principals) == 0 {
		// Default to normalized candidates from identity (username, email local-part)
		return id.NormalizedUsernames()
	}
	out := make([]string, 0, len(a.cfg.Principals))
	emailLocal := id.Email
	if i := strings.IndexByte(emailLocal, '@'); i > 0 {
		emailLocal = emailLocal[:i]
	}
	for _, t := range a.cfg.Principals {
		s := strings.ReplaceAll(t, "{username}", id.Username)
		s = strings.ReplaceAll(s, "{emailLocal}", emailLocal)
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func intersectsFold(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	m := map[string]struct{}{}
	for _, s := range a {
		m[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	for _, s := range b {
		if _, ok := m[strings.ToLower(strings.TrimSpace(s))]; ok {
			return true
		}
	}
	return false
}

// String implements fmt.Stringer to aid logging/debugging (non-PII).
func (c OIDCAuthorizerConfig) String() string {
	return fmt.Sprintf("roles=%d groups=%d principals=%d ttl=%s/%s", len(c.AllowRoles), len(c.AllowGroups), len(c.Principals), c.DefaultTTL, c.MaxTTL)
}
