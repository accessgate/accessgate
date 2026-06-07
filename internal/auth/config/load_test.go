package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_JSONFileAndEnvOverride(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://env-idp.example.com")

	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	cfgJSON := `{
  "oidc_issuer": "https://file-idp.example.com",
  "oidc_redirect_uri": "https://app.example.com/callback",
  "oidc_client_id": "client-id",
  "oidc_client_secret": "real-client-secret",
  "redis_url": "redis://localhost:6379",
  "cookie_signing_secret": "real-cookie-signing-secret",
  "app_base_url": "https://app.example.com"
}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(context.Background(), path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDCIssuer != "https://env-idp.example.com" {
		t.Fatalf("expected env override issuer, got %q", cfg.OIDCIssuer)
	}
	if cfg.HTTPPort != "8080" {
		t.Fatalf("expected default HTTPPort 8080, got %q", cfg.HTTPPort)
	}
	if cfg.CookieName == "" {
		t.Fatal("expected default cookie name to be applied")
	}
}

// TestLoad_CommaScopesEnvOnly is the v1.0 config-freeze guard for the
// CommaStrings list field via env with NO config file present (#103). A
// comma-separated OIDC_SCOPES must populate the OIDCScopes slice; before the
// configload fix this failed to decode ("expected slice ... got string").
func TestLoad_CommaScopesEnvOnly(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("OIDC_REDIRECT_URI", "https://app.example.com/callback")
	t.Setenv("OIDC_CLIENT_ID", "client-id")
	t.Setenv("OIDC_CLIENT_SECRET", "real-client-secret")
	t.Setenv("REDIS_URL", "redis://localhost:6379")
	t.Setenv("COOKIE_SIGNING_SECRET", "real-cookie-signing-secret")
	t.Setenv("APP_BASE_URL", "https://app.example.com")
	t.Setenv("OIDC_SCOPES", "openid,profile,email")

	cfg, err := Load(context.Background(), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.OIDCScopesSlice()
	want := []string{"openid", "profile", "email"}
	if len(got) != len(want) {
		t.Fatalf("OIDCScopes: got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OIDCScopes[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
