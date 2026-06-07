package main

import (
	"os"
	"path/filepath"
	"testing"
)

const validAuthConfigJSON = `{
  "redis_url": "redis://localhost:6379",
  "oidc_issuer": "https://issuer.example",
  "oidc_redirect_uri": "https://app/cb",
  "oidc_client_id": "x",
  "oidc_client_secret": "secret-value",
  "oidc_scopes": ["openid", "profile"],
  "oidc_audience": "accessgate",
  "oidc_claims_source": "id_token",
  "session_redis_prefix": "auth",
  "session_ttl_seconds": 36000,
  "session_pkce_ttl_seconds": 300,
  "session_refresh_lock_ttl_seconds": 15,
  "session_refresh_early_seconds": 60,
  "cookie_name": "__Host-ess_session",
  "cookie_signing_secret": "01234567890123456789012345678901",
  "cookie_secure": true,
  "cookie_same_site": "lax",
  "cookie_domain": "",
  "app_base_url": "https://app.example.com",
  "login_error_redirect_path": "/login?error=oidc_error",
  "allowed_redirect_origins": ["https://app.example.com"],
  "allowed_redirect_paths": ["/"],
  "http_port": "8080",
  "admin_secret": "",
  "post_login_webhook_url": "",
  "cors_allowed_origins": [],
  "provider_plugin_id": ""
}`

func TestFileURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"windows", `C:\a\b.json`, "file:///C:/a/b.json"},
		{"posix", "/a/b.json", "file:///a/b.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileURL(tc.in); got != tc.want {
				t.Fatalf("fileURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeBinary(t *testing.T) {
	b, w := normalizeBinary("  AGENT  ")
	if b != "auth" || w == "" {
		t.Fatalf("got %q warn %q", b, w)
	}
	b2, w2 := normalizeBinary("proxy")
	if b2 != "proxy" || w2 != "" {
		t.Fatal(b2, w2)
	}
}

func TestRunValidAuthConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(validAuthConfigJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(p, "auth"); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsUnknownFieldBySchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{
  "redis_url": "redis://localhost:6379",
  "oidc_issuer": "https://issuer.example",
  "oidc_redirect_uri": "https://app/cb",
  "oidc_client_id": "x",
  "oidc_client_secret": "secret-value",
  "oidc_scopes": ["openid", "profile"],
  "oidc_audience": "accessgate",
  "oidc_claims_source": "id_token",
  "session_redis_prefix": "auth",
  "session_ttl_seconds": 36000,
  "session_pkce_ttl_seconds": 300,
  "session_refresh_lock_ttl_seconds": 15,
  "session_refresh_early_seconds": 60,
  "cookie_name": "__Host-ess_session",
  "cookie_signing_secret": "01234567890123456789012345678901",
  "cookie_secure": true,
  "cookie_same_site": "lax",
  "cookie_domain": "",
  "app_base_url": "https://app.example.com",
  "login_error_redirect_path": "/login?error=oidc_error",
  "allowed_redirect_origins": ["https://app.example.com"],
  "allowed_redirect_paths": ["/"],
  "http_port": "8080",
  "admin_secret": "",
  "post_login_webhook_url": "",
  "cors_allowed_origins": [],
  "provider_plugin_id": "",
  "unknown_key": "nope"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(p, "auth"); err == nil {
		t.Fatal("expected schema validation error")
	}
}
