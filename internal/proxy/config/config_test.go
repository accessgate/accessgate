package config

import (
	"context"
	"os"
	"testing"

	"github.com/ArmanAvanesyan/go-config/config"
	"github.com/ArmanAvanesyan/go-config/providers/source/env"
)

func TestValidate_RequiredFields(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty config")
	}
	cfg.UpstreamURL = "http://localhost:3000"
	cfg.AuthURL = "http://localhost:8080"
	cfg.AllowPrivateUpstreams = true // test uses loopback addresses
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestValidateGRPCUpstreamSSRF(t *testing.T) {
	// Loopback / private addresses are rejected.
	for _, addr := range []string{
		"127.0.0.1:9090",
		"10.0.0.5:9090",
		"192.168.1.10:9090",
		"169.254.169.254:80", // cloud metadata
	} {
		if err := validateGRPCUpstreamSSRF(addr); err == nil {
			t.Errorf("expected SSRF rejection for %q", addr)
		}
	}

	// Malformed host:port forms are rejected.
	for _, addr := range []string{
		"not-a-host-port",
		"host-without-port",
		":9090",      // no host
		"127.0.0.1:", // no port
	} {
		if err := validateGRPCUpstreamSSRF(addr); err == nil {
			t.Errorf("expected error for malformed addr %q", addr)
		}
	}

	// A public IP literal passes (no DNS, deterministic).
	if err := validateGRPCUpstreamSSRF("203.0.113.10:9090"); err != nil {
		t.Errorf("expected public address to pass: %v", err)
	}
}

func TestValidate_GRPCUpstreamWiring(t *testing.T) {
	base := func() *Config {
		return &Config{
			UpstreamURL: "http://203.0.113.10:3000",
			AuthURL:     "http://203.0.113.11:8080",
		}
	}

	// Loopback gRPC upstream is rejected by Validate when private upstreams are
	// not allowed.
	cfg := base()
	cfg.GRPCUpstreamAddr = "127.0.0.1:9090"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected SSRF error for loopback grpc_upstream_addr via Validate")
	}

	// With allow_private_upstreams, the loopback address is accepted.
	cfg = base()
	cfg.AllowPrivateUpstreams = true
	cfg.GRPCUpstreamAddr = "127.0.0.1:9090"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with allow_private_upstreams: %v", err)
	}

	// Empty grpc_upstream_addr keeps legacy behavior and passes validation.
	cfg = base()
	cfg.GRPCUpstreamAddr = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty grpc_upstream_addr should validate: %v", err)
	}
}

func TestValidate_ProxyPathPrefix(t *testing.T) {
	// AllowPrivateUpstreams=true because "u" and "a" are non-resolvable hostnames used to test prefix normalization only.
	cfg := &Config{UpstreamURL: "http://u", AuthURL: "http://a", ProxyPathPrefix: "graphql", AllowPrivateUpstreams: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.ProxyPathPrefix != "/graphql" {
		t.Errorf("expected ProxyPathPrefix to get leading slash: %q", cfg.ProxyPathPrefix)
	}
}

func TestLoadFromEnv(t *testing.T) {
	if err := os.Setenv("UPSTREAM_URL", "http://localhost:3000"); err != nil {
		t.Fatalf("Setenv UPSTREAM_URL: %v", err)
	}
	if err := os.Setenv("AUTH_URL", "http://localhost:8080"); err != nil {
		t.Fatalf("Setenv AUTH_URL: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("UPSTREAM_URL"); err != nil {
			t.Fatalf("Unsetenv UPSTREAM_URL: %v", err)
		}
		if err := os.Unsetenv("AUTH_URL"); err != nil {
			t.Fatalf("Unsetenv AUTH_URL: %v", err)
		}
	}()

	var cfg Config
	err := config.New().AddSource(env.New("")).Load(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("Load from env: %v", err)
	}
	cfg.ApplyDefaults()
	cfg.AllowPrivateUpstreams = true // test uses loopback addresses
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.UpstreamURL != "http://localhost:3000" {
		t.Errorf("UpstreamURL: got %q", cfg.UpstreamURL)
	}
	if cfg.AuthURL != "http://localhost:8080" {
		t.Errorf("AuthURL: got %q", cfg.AuthURL)
	}
}

func TestPolicyFallbackAllowDefaultsDeny(t *testing.T) {
	c := &Config{
		UpstreamURL: "https://upstream.example.com",
		AuthURL:     "https://auth.example.com",
	}
	c.ApplyDefaults()

	if c.PolicyFallbackAllow == nil {
		t.Fatal("PolicyFallbackAllow should be set by ApplyDefaults")
	}
	if *c.PolicyFallbackAllow {
		t.Error("PolicyFallbackAllow should default to false (deny), not true")
	}
}
