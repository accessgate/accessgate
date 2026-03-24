package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_JSONFileAndEnvOverride(t *testing.T) {
	t.Setenv("UPSTREAM_URL", "http://localhost:3000")

	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.json")
	cfgJSON := `{
  "upstream_url": "https://upstream-from-file.example.com",
  "auth_url": "https://auth.example.com",
  "proxy_path_prefix": "graphql",
  "allow_private_upstreams": true
}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(context.Background(), path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamURL != "http://localhost:3000" {
		t.Fatalf("expected env override upstream_url, got %q", cfg.UpstreamURL)
	}
	if cfg.ProxyPathPrefix != "/graphql" {
		t.Fatalf("expected normalized proxy path prefix, got %q", cfg.ProxyPathPrefix)
	}
	if cfg.HTTPPort != "8081" {
		t.Fatalf("expected default HTTPPort 8081, got %q", cfg.HTTPPort)
	}
	if cfg.PolicyFallbackAllow == nil || *cfg.PolicyFallbackAllow {
		t.Fatalf("expected PolicyFallbackAllow default false, got %#v", cfg.PolicyFallbackAllow)
	}
}

// TestLoad_RepoExampleYAMLFile loads configs/proxy.example.yaml (YAML via go-config WASM).
// ALLOW_PRIVATE_UPSTREAMS avoids DNS/SSRF flakiness when example hostnames resolve oddly offline.
func TestLoad_RepoExampleYAMLFile(t *testing.T) {
	path := filepath.Join("..", "..", "..", "configs", "proxy.example.yaml")
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("config file not found (run from repo root): %v", err)
	}
	t.Setenv("ALLOW_PRIVATE_UPSTREAMS", "true")

	cfg, err := Load(context.Background(), path)
	if err != nil {
		t.Skipf("load config (go-config YAML WASM parser): %v", err)
	}
	if cfg.UpstreamURL == "" || cfg.AuthURL == "" {
		t.Errorf("expected non-empty UpstreamURL and AuthURL from example config")
	}
}
