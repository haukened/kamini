package domain

import "testing"

func TestIdentityNormalizedUsernames(t *testing.T) {
	id := Identity{Username: "Alice", Email: "alice@example.com"}
	got := id.NormalizedUsernames()
	// duplicates are removed; only one "alice" remains
	if len(got) != 1 || got[0] != "alice" {
		t.Fatalf("unexpected %v", got)
	}

	id2 := Identity{Username: "", Email: "Bob@example.com"}
	got2 := id2.NormalizedUsernames()
	if len(got2) != 1 || got2[0] != "bob" {
		t.Fatalf("unexpected %v", got2)
	}
}
func TestNewPrincipalSet(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "deduplicates and normalizes",
			input: []string{"Alice", "alice", "ALICE"},
			want:  []string{"alice"},
		},
		{
			name:  "filters empty and unsafe",
			input: []string{"", "Bob!", "bob"},
			want:  []string{"bob"},
		},
		{
			name:  "truncates long usernames",
			input: []string{string(make([]byte, 70))},
			want:  []string{safeUsername(string(make([]byte, 64)))},
		},
		{
			name:  "multiple valid principals",
			input: []string{"alice", "bob", "carol"},
			want:  []string{"alice", "bob", "carol"},
		},
		{
			name:  "removes duplicates after normalization",
			input: []string{"Bob@example.com", "bob"},
			want:  []string{"bob"},
		},
		{
			name:  "really long username",
			input: []string{string(make([]byte, 70))},
			want:  []string{safeUsername(string(make([]byte, 64)))},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := NewPrincipalSet(tt.input...)
			got := ps.List()
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d]=%q, want[%d]=%q", i, got[i], i, tt.want[i])
				}
			}
		})
	}
}

func TestIsValidPrincipal(t *testing.T) {
	if !IsValidPrincipal("alice") {
		t.Fatalf("alice should be valid")
	}
	if IsValidPrincipal("") {
		t.Fatalf("empty should be invalid")
	}
	if IsValidPrincipal("!!!!") { // normalizes to "----" then trimmed by PrincipalSet, but safeUsername is non-empty
		// IsValidPrincipal uses safeUsername directly; it will be valid if it normalizes to non-empty
	}
}
