//go:build ignore

// Gateway adapter integration tests. This file is excluded from the build until
// pkg/plugins/caddy, krakend, and traefik packages exist in this module (see plugin repos).
package plugins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/plugins/caddy"
	"github.com/accessgate/accessgate/internal/plugins/krakend"
	"github.com/accessgate/accessgate/internal/plugins/traefik"
	"github.com/accessgate/accessgate/internal/authz"
)

var testIntegrationDescriptor = plugin.PluginDescriptor{
	ID: "test-integration", Kind: plugin.PluginKindIntegration,
	Name: "Test", Version: "0.0.0", Capabilities: []plugin.Capability{"integration:test"},
}

type testEngine struct{}

func (testEngine) Handle(_ context.Context, _ *authz.Request) (*authz.Response, error) {
	return &authz.Response{Allow: true}, nil
}

// engineWithHeaders returns Allow with upstream headers for handler integration tests.
type engineWithHeaders struct {
	headers map[string]string
}

func (e engineWithHeaders) Handle(_ context.Context, _ *authz.Request) (*authz.Response, error) {
	return &authz.Response{Allow: true, UpstreamHeaders: e.headers}, nil
}

func TestKrakendNewPluginStoresEngine(t *testing.T) {
	e := testEngine{}
	p := krakend.NewPlugin(e, testIntegrationDescriptor, "")
	if p == nil {
		t.Fatal("expected non-nil Plugin")
	}
	if p.Descriptor().ID != testIntegrationDescriptor.ID {
		t.Errorf("descriptor id: got %s", p.Descriptor().ID)
	}
	if h := p.Handler(nil); h == nil {
		t.Error("Handler() should return non-nil")
	}
}

func TestTraefikNewMiddlewareStoresEngine(t *testing.T) {
	e := testEngine{}
	m := traefik.NewMiddleware(e, testIntegrationDescriptor, "", nil)
	if m == nil {
		t.Fatal("expected non-nil Middleware")
	}
	if m.Descriptor().ID != testIntegrationDescriptor.ID {
		t.Errorf("descriptor id: got %s", m.Descriptor().ID)
	}
	if h := m.Handler(nil); h == nil {
		t.Error("Handler() should return non-nil")
	}
}

func TestCaddyNewMiddlewareStoresEngine(t *testing.T) {
	e := testEngine{}
	m := caddy.NewMiddleware(e, testIntegrationDescriptor, "")
	if m == nil {
		t.Fatal("expected non-nil Middleware")
	}
	if m.Descriptor().ID != testIntegrationDescriptor.ID {
		t.Errorf("descriptor id: got %s", m.Descriptor().ID)
	}
	if h := m.Handler(nil); h == nil {
		t.Error("Handler() should return non-nil")
	}
}

func TestCaddyHandler_Allow_Returns200AndHeaders(t *testing.T) {
	e := engineWithHeaders{headers: map[string]string{"X-User-Id": "alice", "X-Roles": "admin"}}
	handler := caddy.Handler(e, nil, "")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-User-Id"); got != "alice" {
		t.Errorf("X-User-Id: got %q", got)
	}
	if got := rr.Header().Get("X-Roles"); got != "admin" {
		t.Errorf("X-Roles: got %q", got)
	}
}

func TestTraefikHandler_Allow_Returns200AndHeaders(t *testing.T) {
	e := engineWithHeaders{headers: map[string]string{"X-User-Id": "bob"}}
	m := traefik.NewMiddleware(e, testIntegrationDescriptor, "", []string{"X-User-Id"})
	handler := m.Handler(nil)
	if handler == nil {
		t.Fatal("Handler() is nil")
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/bar", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-User-Id"); got != "bob" {
		t.Errorf("X-User-Id: got %q", got)
	}
}

func TestKrakendHandler_Allow_Returns200AndHeaders(t *testing.T) {
	e := engineWithHeaders{headers: map[string]string{"X-User-Id": "carol"}}
	p := krakend.NewPlugin(e, testIntegrationDescriptor, "")
	handler := p.Handler(nil)
	if handler == nil {
		t.Fatal("Handler() is nil")
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-User-Id"); got != "carol" {
		t.Errorf("X-User-Id: got %q", got)
	}
}
