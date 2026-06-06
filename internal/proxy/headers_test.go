package proxy

import (
	"net/http"
	"testing"

	"github.com/accessgate/accessgate/internal/proxy/config"
)

func TestBuildUpstreamHeadersBearerAndClaims(t *testing.T) {
	cfg := &config.Config{
		HeaderUserIDClaim:   "sub",
		HeaderEmailClaim:    "email",
		HeaderRolesClaim:    "roles",
		HeaderAdminRole:     "admin",
		HeaderTenantIDClaim: "tid",
	}
	claims := map[string]any{
		"sub":   "u1",
		"email": "e@x.com",
		"roles": []interface{}{"admin", "user"},
		"tid":   "t99",
	}
	tenant := map[string]any{"tenant_id": "fromctx"}
	h := BuildUpstreamHeaders(cfg, "tok", claims, tenant)
	if h["Authorization"] != "Bearer tok" {
		t.Fatal(h["Authorization"])
	}
	if h["X-User-Id"] != "u1" || h["X-User-Email"] != "e@x.com" {
		t.Fatal(h)
	}
	if h["X-Roles"] != "admin,user" || h["X-Is-Admin"] != "true" {
		t.Fatal(h)
	}
	// Claims mapping runs after tenant context and overwrites X-Tenant-Id when set.
	if h["X-Tenant-Id"] != "t99" {
		t.Fatal(h["X-Tenant-Id"])
	}
}

func TestBuildUpstreamHeadersNilClaims(t *testing.T) {
	h := BuildUpstreamHeaders(&config.Config{}, "t", nil, nil)
	if h["Authorization"] != "Bearer t" {
		t.Fatal(h)
	}
	if len(h) != 1 {
		t.Fatal(h)
	}
}

func TestCopyHeaders(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	CopyHeaders(r, map[string]string{"X-A": "1", "X-B": "2"})
	if r.Header.Get("X-A") != "1" {
		t.Fatal(r.Header)
	}
}
