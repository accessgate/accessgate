package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	"github.com/ArmanAvanesyan/accessgate/pkg/auth"
)

type mockAgentService struct{}

func (m *mockAgentService) Session(_ context.Context, _ auth.SessionRequest) (*auth.SessionResponse, error) {
	return &auth.SessionResponse{}, nil
}
func (m *mockAgentService) LoginStart(_ context.Context, _ auth.LoginStartRequest) (*auth.LoginStartResponse, error) {
	return nil, nil
}
func (m *mockAgentService) LoginEnd(_ context.Context, _ auth.LoginEndRequest) (*auth.LoginEndResponse, error) {
	return nil, nil
}
func (m *mockAgentService) Refresh(_ context.Context, _ auth.RefreshRequest) (*auth.RefreshResponse, error) {
	return nil, nil
}
func (m *mockAgentService) Logout(_ context.Context, _ auth.LogoutRequest) (*auth.LogoutResponse, error) {
	return nil, nil
}

func TestNewReturnsServerWithHandler(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080", CookieName: "test", SessionTTLSeconds: 3600}
	s := New(&mockAgentService{}, cfg, nil, nil)
	if s == nil {
		t.Fatalf("expected non-nil Server")
	}
	if s.Handler() == nil {
		t.Fatalf("expected non-nil Handler")
	}
}

func TestPatchInternalSessionRequiresAdminSecret(t *testing.T) {
	cfg := &config.Config{
		HTTPPort: "8080", CookieName: "test", SessionTTLSeconds: 3600,
		AdminSecret: "expected-secret",
	}
	s := New(&mockAgentService{}, cfg, nil, nil)
	h := s.Handler()

	req := httptest.NewRequest(http.MethodPatch, "/internal/session", strings.NewReader(`{"session_id":"x","tenant_context":{"tenant_id":"t"}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing X-Admin-Secret: got status %d, want %d", rr.Code, http.StatusForbidden)
	}

	req2 := httptest.NewRequest(http.MethodPatch, "/internal/session", strings.NewReader(`{"session_id":"x","tenant_context":{"tenant_id":"t"}}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Admin-Secret", "wrong")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("wrong X-Admin-Secret: got status %d, want %d", rr2.Code, http.StatusForbidden)
	}
}

func TestPatchInternalSessionNotRegisteredWithoutAdminSecret(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080", CookieName: "test", SessionTTLSeconds: 3600}
	s := New(&mockAgentService{}, cfg, nil, nil)
	req := httptest.NewRequest(http.MethodPatch, "/internal/session", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("without admin_secret route should be absent: got %d, want %d", rr.Code, http.StatusNotFound)
	}
}
