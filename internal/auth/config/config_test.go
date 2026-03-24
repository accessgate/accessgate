package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmanAvanesyan/go-config/config"
	jsonparser "github.com/ArmanAvanesyan/go-config/providers/parser/json"
	"github.com/ArmanAvanesyan/go-config/providers/source/env"
	"github.com/ArmanAvanesyan/go-config/providers/source/file"
)

func TestValidate_RequiredFields(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty config")
	}
	cfg.OIDCIssuer = "https://idp.example.com"
	cfg.OIDCRedirectURI = "https://app/callback"
	cfg.OIDCClientID = "client"
	cfg.RedisURL = "redis://localhost"
	cfg.CookieSigningSecret = "secret"
	cfg.AppBaseURL = "https://app.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestKeyLayout(t *testing.T) {
	cfg := &Config{SessionRedisPrefix: "auth", SessionTTLSeconds: 3600, SessionPKCETTLSeconds: 300, SessionRefreshLockTTLSeconds: 15}
	layout := cfg.KeyLayout()
	if layout.SessionPrefix != "auth:session:" {
		t.Errorf("SessionPrefix: got %q", layout.SessionPrefix)
	}
	if layout.PKCEPrefix != "auth:pkce:" {
		t.Errorf("PKCEPrefix: got %q", layout.PKCEPrefix)
	}
}

func TestLoadFromEnv(t *testing.T) {
	if err := os.Setenv("OIDC_ISSUER", "https://idp.example.com"); err != nil {
		t.Fatalf("Setenv OIDC_ISSUER: %v", err)
	}
	if err := os.Setenv("OIDC_REDIRECT_URI", "https://app/callback"); err != nil {
		t.Fatalf("Setenv OIDC_REDIRECT_URI: %v", err)
	}
	if err := os.Setenv("OIDC_CLIENT_ID", "client"); err != nil {
		t.Fatalf("Setenv OIDC_CLIENT_ID: %v", err)
	}
	if err := os.Setenv("OIDC_CLIENT_SECRET", "secret"); err != nil {
		t.Fatalf("Setenv OIDC_CLIENT_SECRET: %v", err)
	}
	if err := os.Setenv("REDIS_URL", "redis://localhost:6379"); err != nil {
		t.Fatalf("Setenv REDIS_URL: %v", err)
	}
	if err := os.Setenv("COOKIE_SIGNING_SECRET", "cookie-secret"); err != nil {
		t.Fatalf("Setenv COOKIE_SIGNING_SECRET: %v", err)
	}
	if err := os.Setenv("APP_BASE_URL", "https://app.example.com"); err != nil {
		t.Fatalf("Setenv APP_BASE_URL: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("OIDC_ISSUER"); err != nil {
			t.Fatalf("Unsetenv OIDC_ISSUER: %v", err)
		}
		if err := os.Unsetenv("OIDC_REDIRECT_URI"); err != nil {
			t.Fatalf("Unsetenv OIDC_REDIRECT_URI: %v", err)
		}
		if err := os.Unsetenv("OIDC_CLIENT_ID"); err != nil {
			t.Fatalf("Unsetenv OIDC_CLIENT_ID: %v", err)
		}
		if err := os.Unsetenv("OIDC_CLIENT_SECRET"); err != nil {
			t.Fatalf("Unsetenv OIDC_CLIENT_SECRET: %v", err)
		}
		if err := os.Unsetenv("REDIS_URL"); err != nil {
			t.Fatalf("Unsetenv REDIS_URL: %v", err)
		}
		if err := os.Unsetenv("COOKIE_SIGNING_SECRET"); err != nil {
			t.Fatalf("Unsetenv COOKIE_SIGNING_SECRET: %v", err)
		}
		if err := os.Unsetenv("APP_BASE_URL"); err != nil {
			t.Fatalf("Unsetenv APP_BASE_URL: %v", err)
		}
	}()

	var cfg Config
	err := config.New().AddSource(env.New("")).Load(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("Load from env: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.OIDCIssuer != "https://idp.example.com" {
		t.Errorf("OIDCIssuer: got %q", cfg.OIDCIssuer)
	}
}

// TestLoadFromFile_AgentExampleJSON runs the same load path as cmd/validateconfig
// (file source + go-config + ApplyDefaults + Validate) for configs/auth.example.json.
func TestLoadFromFile_AgentExampleJSON(t *testing.T) {
	// From internal/auth/config we need ../../../configs to reach repo configs/.
	path := filepath.Join("..", "..", "..", "configs", "auth.example.json")
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("config file not found (run from repo root or ensure configs/ exists): %v", err)
	}
	ctx := context.Background()
	loader := config.New().AddSource(file.New(path), jsonparser.New())
	var cfg Config
	if err := loader.Load(ctx, &cfg); err != nil {
		t.Fatalf("Load config: %v", err)
	}
	cfg.ApplyDefaults()
	// Secrets are intentionally blank in the example file (set via env vars in production).
	// Inject test values so Validate() can exercise the full validation path.
	if cfg.OIDCClientSecret == "" {
		cfg.OIDCClientSecret = "test-client-secret"
	}
	if cfg.CookieSigningSecret == "" {
		cfg.CookieSigningSecret = "test-signing-secret-32-bytes-long!"
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.OIDCIssuer == "" || cfg.AppBaseURL == "" {
		t.Errorf("expected non-empty OIDCIssuer and AppBaseURL from example config")
	}
}
