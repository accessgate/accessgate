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

func TestNormalize_LegacySynthesizesDefaultConnector(t *testing.T) {
	cfg := &Config{
		OIDCIssuer:       "https://idp.example.com",
		OIDCRedirectURI:  "https://app/callback",
		OIDCClientID:     "client",
		OIDCClientSecret: "secret",
		ProviderPluginID: "provider:oidc",
	}
	cfg.ApplyDefaults()
	cfg.Normalize()

	if len(cfg.Connectors) != 1 {
		t.Fatalf("expected 1 synthesized connector, got %d", len(cfg.Connectors))
	}
	c := cfg.Connectors[0]
	if c.ID != "default" || !bool(c.Default) {
		t.Errorf("synthesized connector should be id=default,default=true; got id=%q default=%v", c.ID, bool(c.Default))
	}
	if c.OIDCIssuer != "https://idp.example.com" || c.OIDCClientID != "client" {
		t.Errorf("synthesized connector did not copy legacy OIDC fields: %+v", c)
	}
	// Backward compat: prefixes and cookie must match the legacy single-provider layout.
	if got := c.KeyLayout().SessionPrefix; got != "auth:session:" {
		t.Errorf("default connector SessionPrefix = %q, want auth:session: (backward compat)", got)
	}
	if c.CookieName != "__Host-ess_session" {
		t.Errorf("default connector CookieName = %q, want __Host-ess_session", c.CookieName)
	}
	if c.ClaimMapping.AuthoritativeIDClaim != "sub" || c.ClaimMapping.IDKind != "oidc_sub" {
		t.Errorf("default claim mapping = %+v, want sub/oidc_sub", c.ClaimMapping)
	}
}

func TestNormalize_MultiConnectorDefaults(t *testing.T) {
	cfg := &Config{
		RedisURL:            "redis://localhost",
		CookieSigningSecret: "secret",
		AppBaseURL:          "https://app.example.com",
		Connectors: []ConnectorConfig{
			{ID: "sso", Default: true, OIDCIssuer: "https://sso", OIDCRedirectURI: "https://app/cb/sso", OIDCClientID: "a"},
			{ID: "telegram", OIDCIssuer: "https://tg", OIDCRedirectURI: "https://app/cb/tg", OIDCClientID: "b",
				ClaimMapping: ClaimMappingConfig{AuthoritativeIDClaim: "tg_id", IDKind: "telegram_id"}},
		},
	}
	cfg.ApplyDefaults()
	cfg.Normalize()

	tg := cfg.Connectors[1]
	if got := tg.KeyLayout().SessionPrefix; got != "auth:telegram:session:" {
		t.Errorf("telegram SessionPrefix = %q, want auth:telegram:session:", got)
	}
	if tg.CookieName != "__Host-ess_session_telegram" {
		t.Errorf("telegram CookieName = %q, want __Host-ess_session_telegram", tg.CookieName)
	}
	if tg.ClaimMapping.AuthoritativeIDClaim != "tg_id" || tg.ClaimMapping.IDKind != "telegram_id" {
		t.Errorf("telegram claim mapping = %+v, want tg_id/telegram_id", tg.ClaimMapping)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate multi-connector: %v", err)
	}
}

func TestValidateConnectors_Errors(t *testing.T) {
	base := func(conns []ConnectorConfig) *Config {
		c := &Config{RedisURL: "redis://x", CookieSigningSecret: "s", AppBaseURL: "https://app", Connectors: conns}
		c.ApplyDefaults()
		c.Normalize()
		return c
	}
	cases := map[string][]ConnectorConfig{
		"bad id":         {{ID: "bad id", Default: true, OIDCIssuer: "i", OIDCRedirectURI: "r", OIDCClientID: "c"}},
		"missing issuer": {{ID: "x", Default: true, OIDCRedirectURI: "r", OIDCClientID: "c"}},
		"duplicate id": {
			{ID: "x", Default: true, OIDCIssuer: "i", OIDCRedirectURI: "r", OIDCClientID: "c"},
			{ID: "x", OIDCIssuer: "i", OIDCRedirectURI: "r", OIDCClientID: "c"},
		},
		"two defaults": {
			{ID: "x", Default: true, OIDCIssuer: "i", OIDCRedirectURI: "r", OIDCClientID: "c"},
			{ID: "y", Default: true, OIDCIssuer: "i", OIDCRedirectURI: "r", OIDCClientID: "c"},
		},
	}
	for name, conns := range cases {
		t.Run(name, func(t *testing.T) {
			if err := base(conns).Validate(); err == nil {
				t.Errorf("expected validation error for %q", name)
			}
		})
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
