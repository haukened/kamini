package domain

import "testing"

func TestLocalPart(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "alice"},
		{"bob@", "bob"},
		{"no-at-symbol", ""},
		{"@missinglocal", ""},
	}
	for _, tc := range tests {
		if got := localPart(tc.in); got != tc.want {
			t.Fatalf("localPart(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSafeUsername(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{" Alice ", "alice"},
		{"A B", "a-b"},
		{"A/B", "a-b"},
		{"UPPER_case.Name-1", "upper_case.name-1"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := safeUsername(tc.in); got != tc.want {
			t.Fatalf("safeUsername(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// truncation to 64 chars
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXXXX"
	got := safeUsername(long)
	if len(got) != 64 {
		t.Fatalf("safeUsername length = %d, want 64", len(got))
	}
}

func TestUniqueNonEmpty(t *testing.T) {
	got := uniqueNonEmpty([]string{"", "a", "b", "a", "", "b", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCloneStringMap(t *testing.T) {
	tests := []struct {
		in   map[string]string
		want map[string]string
	}{
		{nil, nil},
		{map[string]string{}, nil},
		{map[string]string{"a": "1"}, map[string]string{"a": "1"}},
		{map[string]string{"x": "y", "z": "w"}, map[string]string{"x": "y", "z": "w"}},
	}
	for _, tc := range tests {
		got := cloneStringMap(tc.in)
		if len(tc.want) == 0 {
			if got != nil {
				t.Fatalf("cloneStringMap(%v) = %v, want nil", tc.in, got)
			}
			continue
		}
		if got == nil {
			t.Fatalf("cloneStringMap(%v) = nil, want %v", tc.in, tc.want)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("len = %d, want %d (%v)", len(got), len(tc.want), got)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Fatalf("key %q: got %q, want %q", k, got[k], v)
			}
		}
		// Ensure it's a copy, not the same map
		if len(tc.in) > 0 {
			got["newkey"] = "newval"
			if _, exists := tc.in["newkey"]; exists {
				t.Fatalf("cloneStringMap did not produce a copy")
			}
		}
	}
}

func TestCloneStringSlice(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"a"}, []string{"a"}},
		{[]string{"x", "y", "z"}, []string{"x", "y", "z"}},
	}
	for _, tc := range tests {
		got := cloneStringSlice(tc.in)
		if len(tc.want) == 0 {
			if got != nil {
				t.Fatalf("cloneStringSlice(%v) = %v, want nil", tc.in, got)
			}
			continue
		}
		if got == nil {
			t.Fatalf("cloneStringSlice(%v) = nil, want %v", tc.in, tc.want)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("len = %d, want %d (%v)", len(got), len(tc.want), got)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("[%d] = %q, want %q", i, got[i], tc.want[i])
			}
		}
		// Ensure it's a copy, not the same slice
		if len(tc.in) > 0 {
			got[0] = "changed"
			if tc.in[0] == "changed" {
				t.Fatalf("cloneStringSlice did not produce a copy")
			}
		}
	}
}
