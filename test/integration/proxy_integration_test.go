// Package integration: proxy integration tests (mock agent, mock upstream).
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/plugins/ratelimit"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/internal/proxy"
	"github.com/accessgate/accessgate/internal/proxy/config"
	"github.com/accessgate/accessgate/internal/proxy/httpserver"
)

func newProxyServer(cfg *config.Config, engine policy.Engine, pipelinePlugins []pkgproxy.PipelinePlugin) *httpserver.Server {
	client := proxy.NewAuthClient(cfg.AuthURL, cfg.CookieName)

	proxyEngine := &pkgproxy.DefaultEngine{
		Resolver:        &proxy.AuthPrincipalResolver{Client: client, CookieName: cfg.CookieName},
		Policy:          engine,
		PipelinePlugins: pipelinePlugins,
		UpstreamURL:     cfg.UpstreamURL,
		RequireAuth:     bool(cfg.RequireAuth),
	}

	return httpserver.New(cfg, proxyEngine, nil, nil)
}

// mockAgentServer returns an httptest server that responds to GET /internal/resolve with 200 and principal claims.
func mockAgentServer(t *testing.T, cookieName string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/resolve", func(w http.ResponseWriter, r *http.Request) {
		cookieVal := ""
		if c, _ := r.Cookie(cookieName); c != nil {
			cookieVal = c.Value
		}
		if cookieVal == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":   "at",
			"claims":         map[string]any{"sub": "test-user", "email": "u@example.com"},
			"tenant_context": map[string]any{},
		})
	})
	return httptest.NewServer(mux)
}

// mockUpstreamServer returns an httptest server that records the last request for assertion.
func mockUpstreamServer(t *testing.T) (*httptest.Server, func() *http.Request) {
	t.Helper()
	var lastReq *http.Request
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastReq = r
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	getLast := func() *http.Request {
		mu.Lock()
		defer mu.Unlock()
		return lastReq
	}
	return srv, getLast
}

func TestProxy_AuthenticatedRequest_ForwardsToUpstreamWithHeaders(t *testing.T) {
	agentSrv := mockAgentServer(t, "test_session")
	defer agentSrv.Close()
	upstreamSrv, getLastRequest := mockUpstreamServer(t)
	defer upstreamSrv.Close()

	cfg := &config.Config{
		UpstreamURL:           upstreamSrv.URL,
		ProxyPathPrefix:       "/graphql",
		AuthURL:               agentSrv.URL,
		CookieName:            "test_session",
		RequireAuth:           true,
		AllowPrivateUpstreams: true, // test server runs on loopback
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	proxySrv := newProxyServer(cfg, policy.NewWASMRuntime(policy.DefaultFallbackAllow), nil)

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Cookie", "test_session=any-session-value")
	rr := httptest.NewRecorder()
	proxySrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body %s", rr.Code, rr.Body.String())
	}
	last := getLastRequest()
	if last == nil {
		t.Fatal("upstream did not receive request")
	}
	if last.Header.Get("X-User-Id") != "test-user" {
		t.Errorf("expected X-User-Id=test-user, got %q", last.Header.Get("X-User-Id"))
	}
}

func TestProxy_PolicyBundleEnforcement(t *testing.T) {
	agentSrv := mockAgentServer(t, "test_session")
	defer agentSrv.Close()

	baseCfg := &config.Config{
		UpstreamURL:           "",
		ProxyPathPrefix:       "/graphql",
		AuthURL:               agentSrv.URL,
		CookieName:            "test_session",
		RequireAuth:           true,
		AllowPrivateUpstreams: true, // test servers run on loopback
	}

	makeEngine := func(t *testing.T, allow bool) policy.Engine {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "policy.rego")
		var src string
		if allow {
			src = `package accessgate
decision := {"allow": true, "status_code": 200, "reason": "", "headers": {}, "obligations": {}}`
		} else {
			src = `package accessgate
decision := {"allow": false, "status_code": 403, "reason": "denied by policy", "headers": {}, "obligations": {}}`
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatalf("write rego: %v", err)
		}
		eng := policy.NewRegoEngine(policy.DefaultFallbackDeny)
		if err := eng.Load(p); err != nil {
			t.Fatalf("load rego: %v", err)
		}
		return eng
	}

	t.Run("allow", func(t *testing.T) {
		upstreamSrv, getLast := mockUpstreamServer(t)
		defer upstreamSrv.Close()

		cfg := *baseCfg
		cfg.UpstreamURL = upstreamSrv.URL
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config: %v", err)
		}
		eng := makeEngine(t, true)
		proxySrv := newProxyServer(&cfg, eng, nil)

		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Cookie", "test_session=any-session-value")
		rr := httptest.NewRecorder()
		proxySrv.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body %s", rr.Code, rr.Body.String())
		}
		if getLast() == nil {
			t.Fatal("expected upstream to receive request")
		}
	})

	t.Run("deny", func(t *testing.T) {
		upstreamSrv, getLast := mockUpstreamServer(t)
		defer upstreamSrv.Close()

		cfg := *baseCfg
		cfg.UpstreamURL = upstreamSrv.URL
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config: %v", err)
		}
		eng := makeEngine(t, false)
		proxySrv := newProxyServer(&cfg, eng, nil)

		req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
		req.Header.Set("Cookie", "test_session=any-session-value")
		rr := httptest.NewRecorder()
		proxySrv.Handler().ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body %s", rr.Code, rr.Body.String())
		}
		if getLast() != nil {
			t.Fatal("expected upstream NOT to receive request on deny")
		}
	})
}

func TestProxy_UnauthenticatedRequest_RequireAuth_Returns401(t *testing.T) {
	agentSrv := mockAgentServer(t, "test_session")
	defer agentSrv.Close()
	upstreamSrv, _ := mockUpstreamServer(t)
	defer upstreamSrv.Close()

	cfg := &config.Config{
		UpstreamURL:           upstreamSrv.URL,
		ProxyPathPrefix:       "/graphql",
		AuthURL:               agentSrv.URL,
		CookieName:            "test_session",
		RequireAuth:           true,
		AllowPrivateUpstreams: true, // test server runs on loopback
	}
	cfg.ApplyDefaults()
	_ = cfg.Validate()
	proxySrv := newProxyServer(cfg, policy.NewWASMRuntime(policy.DefaultFallbackAllow), nil)

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rr := httptest.NewRecorder()
	proxySrv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestProxy_PipelineRatelimit_ShortCircuitsPolicyOnDeny(t *testing.T) {
	agentSrv := mockAgentServer(t, "test_session")
	defer agentSrv.Close()

	upstreamSrv, getLastRequest := mockUpstreamServer(t)
	defer upstreamSrv.Close()

	cfg := &config.Config{
		UpstreamURL:           upstreamSrv.URL,
		ProxyPathPrefix:       "/graphql",
		AuthURL:               agentSrv.URL,
		CookieName:            "test_session",
		RequireAuth:           true,
		AllowPrivateUpstreams: true, // test server runs on loopback
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	// Main policy denies by default (503) when policy evaluation is reached.
	eng := policy.NewWASMRuntime(policy.DefaultFallbackDeny)

	// Rate limit denies on the second request for the same IP.
	rl := ratelimit.New()
	if err := rl.Configure(context.Background(), map[string]any{
		"name":                "rl-1",
		"requests_per_minute": 1,
		"burst":               1,
		"key_strategy":        "ip",
	}); err != nil {
		t.Fatalf("ratelimit Configure: %v", err)
	}
	pipelinePlugins := []pkgproxy.PipelinePlugin{rl}

	proxySrv := newProxyServer(cfg, eng, pipelinePlugins)

	req1 := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req1.Header.Set("Cookie", "test_session=any-session-value")
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	rr1 := httptest.NewRecorder()
	proxySrv.Handler().ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on first request (policy deny), got %d body %s", rr1.Code, rr1.Body.String())
	}
	if getLastRequest() != nil {
		t.Fatal("expected upstream NOT to receive first request")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req2.Header.Set("Cookie", "test_session=any-session-value")
	req2.Header.Set("X-Forwarded-For", "1.1.1.1")
	rr2 := httptest.NewRecorder()
	proxySrv.Handler().ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request (rate limit deny), got %d body %s", rr2.Code, rr2.Body.String())
	}
	if getLastRequest() != nil {
		t.Fatal("expected upstream NOT to receive second request")
	}
}
