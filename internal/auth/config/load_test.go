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
