package config

import (
	"context"
	"os"
	"testing"
	"time"

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

	if c.PolicyFallbackAllow {
		t.Error("PolicyFallbackAllow should default to false (deny), not true")
	}
}

func TestPolicyReloadDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()
	if c.PolicyReloadEnabled {
		t.Error("policy_reload_enabled should default to false")
	}
	if c.PolicyReloadInterval != DefaultPolicyReloadInterval.String() {
		t.Errorf("policy_reload_interval default: got %q, want %q", c.PolicyReloadInterval, DefaultPolicyReloadInterval.String())
	}
	if got := c.PolicyReloadIntervalDuration(); got != DefaultPolicyReloadInterval {
		t.Errorf("PolicyReloadIntervalDuration: got %s, want %s", got, DefaultPolicyReloadInterval)
	}
}

func TestPolicyReloadIntervalValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			UpstreamURL:           "http://upstream",
			AuthURL:               "http://auth",
			AllowPrivateUpstreams: true,
		}
	}

	// Unparseable duration is rejected.
	c := base()
	c.PolicyReloadInterval = "not-a-duration"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unparseable policy_reload_interval")
	}

	// Below the minimum is rejected.
	c = base()
	c.PolicyReloadInterval = "100ms"
	if err := c.Validate(); err == nil {
		t.Fatalf("expected error for policy_reload_interval below %s", MinPolicyReloadInterval)
	}

	// A sane value passes.
	c = base()
	c.PolicyReloadInterval = "5s"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected 5s to validate, got %v", err)
	}
	if got := c.PolicyReloadIntervalDuration(); got != 5*time.Second {
		t.Fatalf("PolicyReloadIntervalDuration: got %s, want 5s", got)
	}
}

func TestNormalize_LegacySynthesizesDefaultRoute(t *testing.T) {
	cfg := &Config{
		UpstreamURL:           "http://upstream:3000",
		AuthURL:               "http://auth:8080",
		RequireAuth:           true,
		AllowPrivateUpstreams: true,
	}
	cfg.ApplyDefaults()
	cfg.Normalize()

	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 synthesized route, got %d", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.ID != "default" {
		t.Errorf("synthesized route id = %q, want default", r.ID)
	}
	if r.PathPrefix != "/graphql" {
		t.Errorf("synthesized route path_prefix = %q, want /graphql (legacy default)", r.PathPrefix)
	}
	if r.UpstreamURL != "http://upstream:3000" {
		t.Errorf("synthesized route upstream = %q", r.UpstreamURL)
	}
	if !bool(r.RequireAuth) {
		t.Error("synthesized route should inherit RequireAuth=true")
	}
	if r.UnauthenticatedMode != UnauthModeAPI401 {
		t.Errorf("synthesized route unauth mode = %q, want api_401", r.UnauthenticatedMode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate legacy-synthesized: %v", err)
	}
}

func TestNormalize_MultiRoute(t *testing.T) {
	cfg := &Config{
		AuthURL:               "http://auth:8080",
		AllowPrivateUpstreams: true,
		Routes: []RouteConfig{
			{ID: "web", PathPrefix: "app", UpstreamURL: "http://web:3000", UnauthenticatedMode: UnauthModeHTMLRedirect, LoginRedirectURL: "https://auth/login"},
			{ID: "api", PathPrefix: "/graphql", UpstreamURL: "http://api:4000"},
		},
	}
	cfg.ApplyDefaults()
	cfg.Normalize()

	if cfg.Routes[0].PathPrefix != "/app" {
		t.Errorf("route path_prefix should be normalized with leading slash, got %q", cfg.Routes[0].PathPrefix)
	}
	if cfg.Routes[1].UnauthenticatedMode != UnauthModeAPI401 {
		t.Errorf("route api unauth mode should default to api_401, got %q", cfg.Routes[1].UnauthenticatedMode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate multi-route: %v", err)
	}
}

func TestValidateRoutes_Errors(t *testing.T) {
	base := func(routes []RouteConfig) *Config {
		c := &Config{AuthURL: "http://auth", AllowPrivateUpstreams: true, Routes: routes}
		c.ApplyDefaults()
		c.Normalize()
		return c
	}
	cases := map[string][]RouteConfig{
		"missing path":         {{ID: "x", UpstreamURL: "http://u"}},
		"missing upstream":     {{ID: "x", PathPrefix: "/a"}},
		"bad unauth mode":      {{ID: "x", PathPrefix: "/a", UpstreamURL: "http://u", UnauthenticatedMode: "bogus"}},
		"redirect without url": {{ID: "x", PathPrefix: "/a", UpstreamURL: "http://u", UnauthenticatedMode: UnauthModeHTMLRedirect}},
		"duplicate id": {
			{ID: "x", PathPrefix: "/a", UpstreamURL: "http://u"},
			{ID: "x", PathPrefix: "/b", UpstreamURL: "http://u"},
		},
	}
	for name, routes := range cases {
		t.Run(name, func(t *testing.T) {
			if err := base(routes).Validate(); err == nil {
				t.Errorf("expected validation error for %q", name)
			}
		})
	}
}

func TestPolicyReloadEnabledRequiresBundlePath(t *testing.T) {
	c := &Config{
		UpstreamURL:           "http://upstream",
		AuthURL:               "http://auth",
		AllowPrivateUpstreams: true,
		PolicyReloadEnabled:   true,
		// PolicyBundlePath intentionally empty.
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected policy_reload_enabled without policy_bundle_path to be rejected")
	}
	c.PolicyBundlePath = "/etc/accessgate/policy.wasm"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected validation to pass once bundle path is set, got %v", err)
	}
}
