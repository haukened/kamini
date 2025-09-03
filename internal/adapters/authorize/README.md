# OIDC Authorizer (policy bridge)

Maps `domain.Identity` to a `domain.PolicyDecision` using simple role/group rules and principal templates.

Highlights
- Pure logic; construct once and reuse.
- Allow if any role/group matches; otherwise deny with a structured code.
- Principals: defaults to normalized username/email local-part, or use templates like `{username}` / `{emailLocal}`.
- TTL: uses requested TTL from the request context, with defaults and clamping handled by domain TTL.

Quick start
```go
a := authorize.NewOIDCAuthorizer(authorize.OIDCAuthorizerConfig{
  AllowRoles:  []string{"dev", "ops"},
  AllowGroups: []string{"engineering"},
  Principals:  []string{"{username}", "{emailLocal}"},
  DefaultTTL:  8 * time.Hour,
  MaxTTL:      12 * time.Hour,
})
```

Decide
```go
decision, err := a.Decide(identity, signCtx)
```

Notes
- For more complex policies (time windows, project scoping, quotas), extend the config or plug a different authorizer.
