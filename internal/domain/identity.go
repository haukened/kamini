package domain

import "strings"

// Identity is who the IdP says you are, normalized for our policy logic.
// No tokens, no raw JWTs, just the distilled claims we care about.
type Identity struct {
	Subject  string // stable unique id (sub/oid)
	Username string // preferred username (normalized)
	Email    string
	Roles    []string // app roles > groups
	Groups   []string
	Claims   map[string]any // extra normalized claims (small, not raw token)
}

// NormalizedUsernames returns candidate Unix usernames derived from Identity.
// Lowercase, safe charset, length-limited. Does not hit the OS.
func (i Identity) NormalizedUsernames() []string {
	// e.g., prefer Username; fallback to email local-part.
	// Implement without external deps; keep consistent across platforms.
	return uniqueNonEmpty([]string{
		safeUsername(i.Username),
		safeUsername(localPart(i.Email)),
	})
}

// PrincipalSet is a tiny value-type helper to dedupe/validate principals.
type PrincipalSet struct{ list []string }

func NewPrincipalSet(principals ...string) PrincipalSet {
	m := map[string]struct{}{}
	out := make([]string, 0, len(principals))
	for _, p := range principals {
		// If it looks like an email, prefer its local-part first
		if strings.Contains(p, "@") {
			if lp := localPart(p); lp != "" {
				p = lp
			}
		}
		p = safeUsername(p)
		// Trim trailing punctuation residues, but preserve all-punctuation edge cases
		if t := strings.TrimRight(p, "._-"); t != "" {
			p = t
		}
		if p == "" {
			continue
		}
		if _, ok := m[p]; ok {
			continue
		}
		m[p] = struct{}{}
		out = append(out, p)
	}
	return PrincipalSet{list: out}
}

func (ps PrincipalSet) List() []string { return append([]string(nil), ps.list...) }

// NormalizePrincipals returns a deduplicated, normalized list of principals.
func NormalizePrincipals(in []string) []string { return NewPrincipalSet(in...).List() }

// IsValidPrincipal returns whether a principal normalizes to a non-empty value.
func IsValidPrincipal(s string) bool { return safeUsername(s) != "" }
