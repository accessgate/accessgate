package ratelimit

import (
	"context"
	"testing"

	"github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/pkg/token"
)

func configuredPlugin(t *testing.T, cfg map[string]any) *Plugin {
	t.Helper()
	p := New()
	if err := p.Configure(context.Background(), cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

func TestRateLimit_PrincipalStrategy(t *testing.T) {
	p := configuredPlugin(t, map[string]any{
		"name":                "rl1",
		"requests_per_minute": 1,
		"burst":               1,
		"key_strategy":        "principal",
	})

	req := &authz.Request{Path: "/graphql"}
	principal := &token.Principal{Subject: "user-1"}

	d1, err := p.Handle(context.Background(), req, principal)
	if err != nil {
		t.Fatalf("Handle 1: %v", err)
	}
	if d1 != nil {
		t.Fatalf("expected nil decision on first request, got %#v", d1)
	}

	d2, err := p.Handle(context.Background(), req, principal)
	if err != nil {
		t.Fatalf("Handle 2: %v", err)
	}
	if d2 == nil || d2.Allow || d2.StatusCode != 429 {
		t.Fatalf("expected deny 429 on second request, got %#v", d2)
	}
}

func TestRateLimit_HeaderStrategy_BucketsPerHeaderValue(t *testing.T) {
	p := configuredPlugin(t, map[string]any{
		"name":                "rl1",
		"requests_per_minute": 1,
		"burst":               1,
		"key_strategy":        "header",
		"header_name":         "X-Test",
	})

	reqA := &authz.Request{
		Path: "/graphql",
		Headers: map[string]string{
			"X-Test": "A",
		},
	}
	reqB := &authz.Request{
		Path: "/graphql",
		Headers: map[string]string{
			"X-Test": "B",
		},
	}

	// First request for A should allow.
	if d, _ := p.Handle(context.Background(), reqA, nil); d != nil {
		t.Fatalf("expected allow for header=A, got %#v", d)
	}

	// First request for B should allow (different bucket).
	if d, _ := p.Handle(context.Background(), reqB, nil); d != nil {
		t.Fatalf("expected allow for header=B, got %#v", d)
	}

	// Second request for A should deny (bucket exhausted).
	d3, err := p.Handle(context.Background(), reqA, nil)
	if err != nil {
		t.Fatalf("Handle A2: %v", err)
	}
	if d3 == nil || d3.Allow || d3.StatusCode != 429 {
		t.Fatalf("expected deny 429 for header=A second request, got %#v", d3)
	}
}

func TestRateLimit_IPStrategy_BucketsPerIP(t *testing.T) {
	p := configuredPlugin(t, map[string]any{
		"name":                "rl1",
		"requests_per_minute": 1,
		"burst":               1,
		"key_strategy":        "ip",
	})

	// RemoteAddr is the actual client IP. TrustedProxies is not configured,
	// so X-Forwarded-For is ignored and RemoteAddr is used as the rate-limit key.
	req1 := &authz.Request{
		Path:       "/graphql",
		RemoteAddr: "1.1.1.1:1234",
		Headers:    map[string]string{},
	}
	req2 := &authz.Request{
		Path:       "/graphql",
		RemoteAddr: "2.2.2.2:5678",
		Headers:    map[string]string{},
	}

	// First request for 1.1.1.1 should allow.
	if d, _ := p.Handle(context.Background(), req1, nil); d != nil {
		t.Fatalf("expected allow for ip=1.1.1.1, got %#v", d)
	}

	// First request for 2.2.2.2 should allow (different bucket).
	if d, _ := p.Handle(context.Background(), req2, nil); d != nil {
		t.Fatalf("expected allow for ip=2.2.2.2, got %#v", d)
	}

	// Second request for 1.1.1.1 should deny.
	d3, err := p.Handle(context.Background(), req1, nil)
	if err != nil {
		t.Fatalf("Handle req1 second: %v", err)
	}
	if d3 == nil || d3.Allow || d3.StatusCode != 429 {
		t.Fatalf("expected deny 429 for ip=1.1.1.1 second request, got %#v", d3)
	}
}

func TestRateLimit_DecisionShape(t *testing.T) {
	p := configuredPlugin(t, map[string]any{
		"name":                "rl1",
		"requests_per_minute": 1,
		"burst":               1,
		"key_strategy":        "header",
		"header_name":         "X-Test",
	})

	req := &authz.Request{
		Path: "/graphql",
		Headers: map[string]string{
			"X-Test": "A",
		},
	}

	_, _ = p.Handle(context.Background(), req, nil)    // allow
	d, err := p.Handle(context.Background(), req, nil) // deny
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if d == nil {
		t.Fatalf("expected decision on deny")
	}
	// Guard: ensure we return exactly the fields the proxy expects.
	want := &policy.Decision{Allow: false, StatusCode: 429}
	if d.Allow != want.Allow || d.StatusCode != want.StatusCode {
		t.Fatalf("unexpected decision core fields: got %#v want %#v", d, want)
	}
	if d.Reason == "" {
		t.Fatalf("expected non-empty reason")
	}
}
