package sdk

import (
	"testing"
	"time"

	"github.com/accessgate/accessgate/pkg/auth"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
	"github.com/accessgate/accessgate/pkg/token"
)

func TestAuthContextFromSessionDerivesPrincipal(t *testing.T) {
	sess := &pkgsession.Session{
		ID:           "sess-1",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		IDToken:      "id-1",
		ExpiresAt:    1710000000,
		Claims: map[string]any{
			"sub":                "user-1",
			"email":              "user@example.com",
			"preferred_username": "u1",
			"name":               "User One",
			"scope":              "openid profile email",
			"realm_access": map[string]any{
				"roles": []any{"admin", "writer"},
			},
			"groups": []any{"g1", "g2"},
		},
		TenantContext: &pkgsession.TenantContext{
			TenantID:   "tenant-1",
			TenantSlug: "acme",
			Status:     "active",
			Locale:     "en",
			Timezone:   "UTC",
		},
	}

	ctx, err := AuthContextFromSession(sess)
	if err != nil {
		t.Fatalf("AuthContextFromSession: %v", err)
	}
	if ctx.GetPrincipal().GetSubject() != "user-1" {
		t.Fatalf("subject = %q", ctx.GetPrincipal().GetSubject())
	}
	if got := ctx.GetPrincipal().GetScopes(); len(got) != 3 || got[0] != "openid" {
		t.Fatalf("scopes = %#v", got)
	}
	if got := ctx.GetPrincipal().GetRoles(); len(got) != 2 || got[0] != "admin" {
		t.Fatalf("roles = %#v", got)
	}
	if ctx.GetSession().GetId() != "sess-1" || ctx.GetSession().GetRefreshToken() != "refresh-1" {
		t.Fatalf("unexpected session = %+v", ctx.GetSession())
	}
	if tenantID := ctx.GetPrincipal().GetTenantContext().AsMap()["tenant_id"]; tenantID != "tenant-1" {
		t.Fatalf("tenant_id = %#v", tenantID)
	}
}

func TestAuthContextFromPrincipalAndSessionPrefersExplicitPrincipal(t *testing.T) {
	principal := &token.Principal{
		Subject:     "principal-1",
		Scopes:      []string{"api:read"},
		Roles:       []string{"reader"},
		Claims:      map[string]any{"sub": "principal-1", "email": "p@example.com"},
		ExpiresAt:   time.Unix(1720000000, 0),
		AccessToken: "explicit-token",
		TenantContext: map[string]any{
			"tenant_id": "tenant-explicit",
		},
	}
	sess := &pkgsession.Session{ID: "sess-2", Claims: map[string]any{"sub": "session-sub"}}

	ctx, err := AuthContextFromPrincipalAndSession(principal, sess)
	if err != nil {
		t.Fatalf("AuthContextFromPrincipalAndSession: %v", err)
	}
	if ctx.GetPrincipal().GetSubject() != "principal-1" {
		t.Fatalf("subject = %q", ctx.GetPrincipal().GetSubject())
	}
	if got := ctx.GetPrincipal().GetRoles(); len(got) != 1 || got[0] != "reader" {
		t.Fatalf("roles = %#v", got)
	}
	if ctx.GetPrincipal().GetAccessToken() != "explicit-token" {
		t.Fatalf("access token = %q", ctx.GetPrincipal().GetAccessToken())
	}
}

func TestSessionResponseFromAuthContext(t *testing.T) {
	ctx, err := AuthContextFromSession(&pkgsession.Session{
		ID:        "sess-3",
		ExpiresAt: 1710000001,
		Claims: map[string]any{
			"sub":                "user-3",
			"email":              "u3@example.com",
			"preferred_username": "u3",
			"name":               "User Three",
			"roles":              []any{"administrator", "editor"},
			"groups":             []any{"staff"},
		},
		TenantContext: &pkgsession.TenantContext{TenantID: "tenant-3"},
	})
	if err != nil {
		t.Fatalf("AuthContextFromSession: %v", err)
	}

	resp := SessionResponseFromAuthContext(ctx)
	if resp == nil || !resp.IsAuthenticated {
		t.Fatalf("unexpected response: %+v", resp)
	}
	want := &auth.SessionUser{
		Sub:               "user-3",
		Email:             "u3@example.com",
		PreferredUsername: "u3",
		Name:              "User Three",
		Roles:             []string{"administrator", "editor"},
		Groups:            []string{"staff"},
		IsAdmin:           true,
	}
	if resp.User == nil {
		t.Fatal("expected user")
	}
	if resp.User.Sub != want.Sub || resp.User.Email != want.Email || !resp.User.IsAdmin {
		t.Fatalf("user = %+v", resp.User)
	}
	if len(resp.User.Roles) != 2 || resp.User.Roles[0] != "administrator" {
		t.Fatalf("roles = %#v", resp.User.Roles)
	}
	if resp.User.TenantContext["tenant_id"] != "tenant-3" {
		t.Fatalf("tenant context = %#v", resp.User.TenantContext)
	}
}

func TestSessionUserFromSessionNilSafe(t *testing.T) {
	if got := SessionUserFromSession(nil); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
	resp := SessionResponseFromAuthContext(nil)
	if resp == nil || resp.IsAuthenticated {
		t.Fatalf("unexpected nil context response: %+v", resp)
	}
}
