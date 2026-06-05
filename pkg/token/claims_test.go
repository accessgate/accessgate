package token

import (
	"reflect"
	"testing"
)

func TestNormalizeClaims_Nil(t *testing.T) {
	if got := NormalizeClaims(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}
}

func TestNormalizeClaims_CopiesInput(t *testing.T) {
	in := map[string]any{
		"sub":   "user-1",
		"email": "u@example.com",
	}
	out := NormalizeClaims(in)
	if &out == &in {
		t.Fatal("expected a copy, got same map reference")
	}
	// Mutating the output must not affect the input.
	out["new"] = "x"
	if _, ok := in["new"]; ok {
		t.Fatal("mutating output leaked into input map")
	}
	if out["sub"] != "user-1" || out["email"] != "u@example.com" {
		t.Fatalf("original keys not preserved: %v", out)
	}
}

func TestNormalizeClaims_Roles(t *testing.T) {
	tests := []struct {
		name      string
		in        map[string]any
		wantRoles []string // nil means "roles" key should be absent
	}{
		{
			name:      "no roles anywhere",
			in:        map[string]any{"sub": "u"},
			wantRoles: nil,
		},
		{
			name: "realm_access roles",
			in: map[string]any{
				"realm_access": map[string]any{
					"roles": []interface{}{"admin", "user"},
				},
			},
			wantRoles: []string{"admin", "user"},
		},
		{
			name: "top-level roles",
			in: map[string]any{
				"roles": []interface{}{"editor"},
			},
			wantRoles: []string{"editor"},
		},
		{
			name: "realm_access takes precedence over top-level",
			in: map[string]any{
				"realm_access": map[string]any{"roles": []interface{}{"realm-role"}},
				"roles":        []interface{}{"top-role"},
			},
			wantRoles: []string{"realm-role"},
		},
		{
			name: "non-string role entries are skipped",
			in: map[string]any{
				"roles": []interface{}{"keep", 42, true, "also-keep"},
			},
			wantRoles: []string{"keep", "also-keep"},
		},
		{
			name: "realm_access roles wrong type falls back to top-level",
			in: map[string]any{
				"realm_access": map[string]any{"roles": "not-an-array"},
				"roles":        []interface{}{"fallback"},
			},
			wantRoles: []string{"fallback"},
		},
		{
			name: "empty realm_access roles array yields no roles key",
			in: map[string]any{
				"realm_access": map[string]any{"roles": []interface{}{}},
			},
			wantRoles: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := NormalizeClaims(tc.in)
			rolesAny, present := out["roles"]
			if tc.wantRoles == nil {
				if present {
					t.Fatalf("expected no normalized roles key, got %v", rolesAny)
				}
				return
			}
			roles, ok := rolesAny.([]string)
			if !ok {
				t.Fatalf("expected roles to be []string, got %T (%v)", rolesAny, rolesAny)
			}
			if !reflect.DeepEqual(roles, tc.wantRoles) {
				t.Fatalf("roles = %v, want %v", roles, tc.wantRoles)
			}
		})
	}
}
