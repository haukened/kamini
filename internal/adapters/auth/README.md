# OIDC Authenticator (server-side)

A thin wrapper around go-oidc that verifies bearer tokens (ID tokens) and maps claims to `domain.Identity`.

Highlights
- Construct once at startup; reuse per request (thread-safe verifier, cached JWKS).
- Configurable claim names; username resolution prefers `preferred_username`, then email local-part, then `sub`.
- Audience (`client_id`) required by default; can be disabled for special setups.

Quick start
```go
import (
  "context"
  auth "github.com/haukened/kamini/internal/adapters/auth"
  sloglog "github.com/haukened/kamini/internal/log"
)

func build(ctx context.Context, l sloglog.Logger) (*auth.OIDCAuthenticator, error) {
  return auth.NewOIDCAuthenticator(ctx, auth.OIDCAuthConfig{
    IssuerURL:  "https://login.microsoftonline.com/<tenant>/v2.0",
    ClientID:   "your-client-id",
    // UsernameClaim: "upn", // optional override
    // RolesClaim:    "roles",
    // GroupsClaim:   "groups",
  }, l)
}
```

Usage per request
```go
id, err := authenticator.Authenticate(r.Context(), r.Header.Get("Authorization"))
```

Notes
- This is a server-side verifier. Clients (CLI) are responsible for obtaining tokens.
- Keep your HTTP client configured with sane timeouts and TLS settings.
