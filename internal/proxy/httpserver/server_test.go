package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/proxy/config"
)

type fakeEngine struct {
	name   string
	resp   *pkgproxy.Response
	called *string
}

func (f *fakeEngine) Handle(_ context.Context, _ *pkgproxy.Request) (*pkgproxy.Response, error) {
	if f.called != nil {
		*f.called = f.name
	}
	return f.resp, nil
}

func baseCfg() *config.Config {
	return &config.Config{AuthURL: "http://auth", CookieName: "test", HTTPPort: "8081"}
}

func TestMultiRoute_DispatchAndRouteMiss(t *testing.T) {
	var called string
	web := fakeEngine{name: "web", resp: &pkgproxy.Response{Allow: false, StatusCode: 401}, called: &called}
	api := fakeEngine{name: "api", resp: &pkgproxy.Response{Allow: false, StatusCode: 401}, called: &called}
	routes := []Route{
		{Config: config.RouteConfig{ID: "web", PathPrefix: "/app", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &web},
		{Config: config.RouteConfig{ID: "api", PathPrefix: "/api", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &api},
	}
	h := NewWithRoutes(baseCfg(), routes, nil, nil).Handler()

	for _, tc := range []struct{ path, want string }{
		{"/app/page", "web"},
		{"/api/graphql", "api"},
	} {
		called = ""
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if called != tc.want {
			t.Errorf("path %s routed to %q, want %q", tc.path, called, tc.want)
		}
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nowhere", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("route miss got %d, want 404", rr.Code)
	}
}

func TestMultiRoute_LongestPrefixWins(t *testing.T) {
	var called string
	root := fakeEngine{name: "root", resp: &pkgproxy.Response{StatusCode: 401}, called: &called}
	apiV2 := fakeEngine{name: "apiv2", resp: &pkgproxy.Response{StatusCode: 401}, called: &called}
	routes := []Route{
		{Config: config.RouteConfig{ID: "root", PathPrefix: "/", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &root},
		{Config: config.RouteConfig{ID: "apiv2", PathPrefix: "/api/v2", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &apiV2},
	}
	h := NewWithRoutes(baseCfg(), routes, nil, nil).Handler()

	called = ""
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v2/users", nil))
	if called != "apiv2" {
		t.Errorf("longest prefix should win, got %q", called)
	}
	called = ""
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/other", nil))
	if called != "root" {
		t.Errorf("catch-all should match, got %q", called)
	}
}

func TestMultiRoute_HostMatching(t *testing.T) {
	var called string
	a := fakeEngine{name: "a", resp: &pkgproxy.Response{StatusCode: 401}, called: &called}
	b := fakeEngine{name: "b", resp: &pkgproxy.Response{StatusCode: 401}, called: &called}
	routes := []Route{
		{Config: config.RouteConfig{ID: "a", Hosts: config.CommaStrings{"a.example"}, PathPrefix: "/", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &a},
		{Config: config.RouteConfig{ID: "b", Hosts: config.CommaStrings{"b.example"}, PathPrefix: "/", UnauthenticatedMode: config.UnauthModeAPI401}, Engine: &b},
	}
	h := NewWithRoutes(baseCfg(), routes, nil, nil).Handler()

	called = ""
	req := httptest.NewRequest(http.MethodGet, "http://b.example:8080/x", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if called != "b" {
		t.Errorf("host b.example should route to b, got %q", called)
	}
}

func TestMultiRoute_HTMLRedirectVsAPI401(t *testing.T) {
	routes := []Route{
		{Config: config.RouteConfig{ID: "web", PathPrefix: "/app"}, Engine: &fakeEngine{resp: &pkgproxy.Response{Allow: false, StatusCode: http.StatusFound, RedirectTo: "https://auth/login"}}},
		{Config: config.RouteConfig{ID: "api", PathPrefix: "/api"}, Engine: &fakeEngine{resp: &pkgproxy.Response{Allow: false, StatusCode: 401, Body: []byte(`{"errors":[{"message":"unauthorized"}]}`)}}},
	}
	h := NewWithRoutes(baseCfg(), routes, nil, nil).Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/app/secret", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://auth/login" {
		t.Errorf("html_redirect: got %d Location=%q", rr.Code, rr.Header().Get("Location"))
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/api/data", nil))
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("api_401: got %d, want 401", rr2.Code)
	}
}

func TestMultiRoute_AllowForwardsToRouteUpstream(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("X-User-Id") != "u1" {
			t.Errorf("upstream missing injected header, got %q", r.Header.Get("X-User-Id"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	routes := []Route{
		{Config: config.RouteConfig{ID: "api", PathPrefix: "/api", UpstreamURL: upstream.URL}, Engine: &fakeEngine{resp: &pkgproxy.Response{Allow: true, UpstreamHeaders: map[string]string{"X-User-Id": "u1"}}}},
	}
	h := NewWithRoutes(baseCfg(), routes, nil, nil).Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/data", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("allow path got %d", rr.Code)
	}
	if gotPath != "/api/data" {
		t.Errorf("upstream path = %q, want /api/data", gotPath)
	}
}

func TestNewReturnsServerWithHandler(t *testing.T) {
	cfg := &config.Config{
		UpstreamURL:     "http://localhost:8002",
		ProxyPathPrefix: "/graphql",
		AuthURL:         "http://localhost:8080",
		CookieName:      "test",
	}
	engine := &pkgproxy.DefaultEngine{UpstreamURL: cfg.UpstreamURL}
	s := New(cfg, engine, nil, nil)
	if s == nil {
		t.Fatalf("expected non-nil Server")
	}
	if s.Handler() == nil {
		t.Fatalf("expected non-nil Handler")
	}
}
