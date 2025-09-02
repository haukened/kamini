package domain

import "testing"

func TestComposeKeyID(t *testing.T) {
	id := Identity{Subject: "sub123", Username: "alice"}
	s := ComposeKeyID(id, 42)
	if s != "42|sub123|alice" {
		t.Fatalf("got %q", s)
	}
}

func TestPolicyDenyAndAttrs(t *testing.T) {
	d := PolicyDeny{Code: DenyIPNotAllowed, Message: "source ip not allowed"}
	if d.Error() == "" {
		t.Fatalf("PolicyDeny.Error empty")
	}
	a := DenyAttrs(d)
	if a["deny_code"] != string(DenyIPNotAllowed) {
		t.Fatalf("DenyAttrs mismatch: %v", a)
	}
}

func TestPolicyDeny_Error(t *testing.T) {
	tests := []struct {
		deny    PolicyDeny
		wantErr string
	}{
		{
			deny:    PolicyDeny{Code: DenyPrincipalNotAllowed, Message: ""},
			wantErr: string(DenyPrincipalNotAllowed),
		},
		{
			deny:    PolicyDeny{Code: DenyTTLTooLarge, Message: "ttl exceeds limit"},
			wantErr: string(DenyTTLTooLarge) + ": ttl exceeds limit",
		},
		{
			deny:    PolicyDeny{Code: DenyDefault, Message: ""},
			wantErr: string(DenyDefault),
		},
		{
			deny:    PolicyDeny{Code: DenyQuotaExceeded, Message: "quota reached"},
			wantErr: string(DenyQuotaExceeded) + ": quota reached",
		},
	}

	for _, tt := range tests {
		got := tt.deny.Error()
		if got != tt.wantErr {
			t.Errorf("PolicyDeny.Error() = %q, want %q", got, tt.wantErr)
		}
	}
}
