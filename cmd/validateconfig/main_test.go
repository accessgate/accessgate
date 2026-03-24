package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
	if err := os.WriteFile(p, []byte(`{"redis_url":"redis://localhost:6379","oidc_issuer":"https://issuer.example","oidc_client_id":"x","oidc_redirect_uri":"https://app/cb","app_base_url":"https://app.example.com","cookie_signing_secret":"01234567890123456789012345678901","http_port":"8080"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(p, "auth"); err != nil {
		t.Fatal(err)
	}
}
