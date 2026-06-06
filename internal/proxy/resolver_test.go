package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/authz"
)

func TestAuthPrincipalResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ResolveResponse{
			AccessToken: "at",
			Claims: map[string]any{
				"sub":   "user1",
				"roles": []string{"admin"},
				"exp":   float64(time.Date(3020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()),
			},
		})
	}))
	defer srv.Close()
	client := NewAuthClient(srv.URL, "session")
	r := &AuthPrincipalResolver{Client: client, CookieName: "session"}
	req := &authz.Request{Cookies: map[string]string{"session": "cookieval"}}
	p, err := r.Resolve(context.Background(), req)
	if err != nil || p == nil || p.Subject != "user1" {
		t.Fatalf("%v %+v", err, p)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "admin" {
		t.Fatal(p.Roles)
	}
	if p.AccessToken != "at" {
		t.Fatal(p.AccessToken)
	}
}

func TestResolveResponseToPrincipal_NormalizesRealmAccessRoles(t *testing.T) {
	p := resolveResponseToPrincipal(&ResolveResponse{
		Claims: map[string]any{
			"sub": "user2",
			"realm_access": map[string]any{
				"roles": []any{"editor", "viewer"},
			},
		},
	})
	if p == nil {
		t.Fatal("expected principal")
	}
	if len(p.Roles) != 2 || p.Roles[0] != "editor" || p.Roles[1] != "viewer" {
		t.Fatalf("unexpected roles: %+v", p.Roles)
	}
	roles, ok := p.Claims["roles"].([]string)
	if !ok {
		t.Fatalf("expected normalized []string roles in claims, got %#v", p.Claims["roles"])
	}
	if len(roles) != 2 || roles[0] != "editor" || roles[1] != "viewer" {
		t.Fatalf("unexpected normalized claims roles: %+v", roles)
	}
}
