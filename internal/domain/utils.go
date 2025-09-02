package domain

import (
	"strings"
	"time"
)

const (
	// PrincipalMaxLen is the maximum length allowed for a single principal/username.
	PrincipalMaxLen = 64
	// DefaultSkew is applied when building cert validity to allow minor clock drift.
	DefaultSkew = 30 * time.Second
)

// localPart extracts and returns the local part of an email address (the substring before the '@' character).
// If the '@' character is not found or is at the start of the string, it returns an empty string.
func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return ""
}

// safeUsername sanitizes the input string to create a safe username.
// It converts the string to lowercase, trims surrounding whitespace,
// and replaces any character not in [a-z, 0-9, '.', '_', '-'] with a dash ('-').
// The resulting username is truncated to a maximum of 64 characters.
// Returns an empty string if the input is empty after trimming.
func safeUsername(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	// Allow a-z 0-9 . _ - ; replace others with '-'
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > PrincipalMaxLen {
		out = out[:PrincipalMaxLen]
	}
	return out
}

// uniqueNonEmpty returns a slice containing only the unique, non-empty strings from the input slice.
// The order of elements is preserved from the input.
// Empty strings and duplicate values are omitted.
func uniqueNonEmpty(in []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// cloneStringMap returns a shallow copy of the provided map or nil if empty.
func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// cloneStringSlice returns a copy of the provided slice or nil if empty.
func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
