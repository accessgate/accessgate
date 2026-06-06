package main

import (
	"testing"

	"github.com/accessgate/accessgate/internal/auth/config"
)

func TestBuildProviderPluginDefaultOIDC(t *testing.T) {
	cfg := &config.Config{
		OIDCIssuer:          "https://issuer.example",
		OIDCClientID:        "cid",
		OIDCRedirectURI:     "https://app/cb",
		RedisURL:            "redis://localhost:6379",
		CookieSigningSecret: "01234567890123456789012345678901",
		AppBaseURL:          "https://app.example.com",
		HTTPPort:            "8080",
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := buildProviderPlugin(cfg)
	if err != nil || p == nil {
		t.Fatalf("%v %v", p, err)
	}
}
