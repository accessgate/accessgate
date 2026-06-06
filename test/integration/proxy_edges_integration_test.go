// Package integration: proxy edge-case integration tests covering upstream
// timeout handling, SSRF / private-upstream blocking, and upstream-header
// construction (claim-derived headers, policy obligations, Cookie stripping).
//
// These complement proxy_integration_test.go and are kept hermetic: every
// dependency (agent resolve, upstream) is an in-process httptest server on
// loopback, and SSRF validation is exercised purely through config.Validate.
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/internal/proxy/config"
)

// mockAgentServerWithClaims is like mockAgentServer but lets a test inject the
// principal claims and tenant context returned by /internal/resolve, so we can
// drive header-construction edge cases.
func mockAgentServerWithClaims(t *testing.T, cookieName string, claims, tenant map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/resolve", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie(cookieName)
		if c == nil || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":   "upstream-access-token",
			"claims":         claims,
			"tenant_context": tenant,
		})
	})
	return httptest.NewServer(mux)
}

// TestProxy_SSRF_PrivateUpstreamBlocking exercises the SSRF guard in
// config.Validate: a private/loopback/link-local upstream must be rejected
// unless allow_private_upstreams is set. We cover loopback, RFC-1918, the AWS
// metadata link-local address, a non-http scheme, and the explicit opt-out.
func TestProxy_SSRF_PrivateUpstreamBlocking(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			ProxyPathPrefix: "/graphql",
			AuthURL:         "http://auth.invalid",
			CookieName:      "test_session",
			RequireAuth:     true,
		}
	}

	t.Run("loopback blocked", func(t *testing.T) {
		cfg := base()
		cfg.UpstreamURL = "http://127.0.0.1:8080"
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected loopback upstream to be blocked by SSRF guard")
		}
	})

	t.Run("rfc1918 blocked", func(t *testing.T) {
		cfg := base()
		cfg.UpstreamURL = "http://10.1.2.3"
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected RFC-1918 upstream to be blocked")
		}
	})

	t.Run("link-local metadata blocked", func(t *testing.T) {
		cfg := base()
		// 169.254.169.254 is the canonical cloud metadata SSRF target.
		cfg.UpstreamURL = "http://169.254.169.254/latest/meta-data/"
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected link-local metadata upstream to be blocked")
		}
	})

	t.Run("non-http scheme blocked", func(t *testing.T) {
		cfg := base()
		cfg.UpstreamURL = "file:///etc/passwd"
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected non-http scheme to be rejected")
		}
	})

	t.Run("allow_private_upstreams opt-out permits loopback", func(t *testing.T) {
		cfg := base()
		cfg.UpstreamURL = "http://127.0.0.1:8080"
		cfg.AllowPrivateUpstreams = true
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected loopback to be allowed with opt-out, got %v", err)
		}
	})
}

// TestProxy_UpstreamTimeout_ReturnsBadGateway verifies that when the upstream
// is slow and the request context deadline elapses, the reverse-proxy path
// surfaces a gateway error (502/504) rather than hanging or panicking.
func TestProxy_UpstreamTimeout_ReturnsBadGateway(t *testing.T) {
	released := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the test releases us (after the client context expires).
		select {
		case <-released:
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	defer close(released)

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rr := httptest.NewRecorder()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := pkgproxy.ProxyToUpstream(ctx, rr, req, slow.URL, nil, nil)
	if err != nil {
		t.Fatalf("ProxyToUpstream returned transport error instead of writing gateway response: %v", err)
	}
	// httputil.ReverseProxy maps an upstream context error to 502 Bad Gateway.
	if rr.Code != http.StatusBadGateway && rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 502/504 on upstream timeout, got %d", rr.Code)
	}
}

// TestProxy_UpstreamHeaders_ConstructionEdges drives the full engine + reverse
// proxy and asserts the upstream-bound header set: claim-derived identity
// headers, the Authorization bearer from the resolved access token, the
// inbound Cookie header being stripped, and policy obligation headers
// (including CRLF-injection stripping).
func TestProxy_UpstreamHeaders_ConstructionEdges(t *testing.T) {
	claims := map[string]any{
		"sub":                "user-42",
		"email":              "user42@example.com",
		"name":               "User Forty Two",
		"preferred_username": "uftwo",
		"realm_access":       map[string]any{"roles": []any{"admin", "editor"}},
	}
	tenant := map[string]any{"tenant_id": "tenant-7"}

	agentSrv := mockAgentServerWithClaims(t, "test_session", claims, tenant)
	defer agentSrv.Close()

	var (
		mu      sync.Mutex
		lastReq *http.Request
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastReq = r.Clone(context.Background())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		UpstreamURL:           upstream.URL,
		ProxyPathPrefix:       "/graphql",
		AuthURL:               agentSrv.URL,
		CookieName:            "test_session",
		RequireAuth:           true,
		AllowPrivateUpstreams: true, // loopback test servers
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	// Policy allows and emits an obligation header plus a CRLF-injection
	// attempt that must be sanitized into a single header line.
	eng := &stubPolicyEngine{decision: &policy.Decision{
		Allow:      true,
		StatusCode: http.StatusOK,
		Obligations: map[string]any{
			"set_header_X_Custom_Tag": "obligation-value",
			"set_header_X_Injected":   "good\r\nX-Evil: bad",
		},
	}}

	proxySrv := newProxyServer(cfg, eng, nil)

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Cookie", "test_session=session-value; other=keepme-in-cookie")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rr := httptest.NewRecorder()
	proxySrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body %s", rr.Code, rr.Body.String())
	}

	mu.Lock()
	got := lastReq
	mu.Unlock()
	if got == nil {
		t.Fatal("upstream did not receive request")
	}

	wantHeaders := map[string]string{
		"X-User-Id":                 "user-42",
		"X-User-Email":              "user42@example.com",
		"X-User-Full-Name":          "User Forty Two",
		"X-User-Preferred-Username": "uftwo",
		"X-Tenant-Id":               "tenant-7",
		"Authorization":             "Bearer upstream-access-token",
		"X-Custom-Tag":              "obligation-value",
	}
	for k, want := range wantHeaders {
		if got := got.Header.Get(k); got != want {
			t.Errorf("upstream header %s: got %q want %q", k, got, want)
		}
	}

	// Roles header is order-independent; assert membership.
	roles := got.Header.Get("X-Roles")
	if !strings.Contains(roles, "admin") || !strings.Contains(roles, "editor") {
		t.Errorf("X-Roles missing expected roles: %q", roles)
	}

	// CRLF injection must be neutralized: no smuggled X-Evil header, and the
	// surviving value must not contain raw CR/LF.
	if got.Header.Get("X-Evil") != "" {
		t.Errorf("CRLF injection leaked a smuggled header X-Evil=%q", got.Header.Get("X-Evil"))
	}
	if v := got.Header.Get("X-Injected"); strings.ContainsAny(v, "\r\n") {
		t.Errorf("X-Injected header value still contains CR/LF: %q", v)
	}

	// The inbound Cookie header must NOT be forwarded upstream.
	if c := got.Header.Get("Cookie"); c != "" {
		t.Errorf("inbound Cookie must be stripped before forwarding, got %q", c)
	}
}

// stubPolicyEngine is a minimal policy.Engine that returns a fixed decision,
// letting header-construction tests avoid loading a real WASM/Rego bundle.
type stubPolicyEngine struct {
	decision *policy.Decision
}

func (s *stubPolicyEngine) Evaluate(_ context.Context, _ policy.Input) (*policy.Decision, error) {
	return s.decision, nil
}

var _ policy.Engine = (*stubPolicyEngine)(nil)
