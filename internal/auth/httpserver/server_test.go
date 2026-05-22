package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	"github.com/ArmanAvanesyan/accessgate/pkg/auth"
	pkgsession "github.com/ArmanAvanesyan/accessgate/pkg/session"
)

type mockAgentService struct{}
type fakeLookupStore struct {
	sess    *pkgsession.Session
	deleted []string
}

func (f *fakeLookupStore) Ping(_ context.Context) error { return nil }
func (f *fakeLookupStore) FindSessionBySubjectEmail(_ context.Context, subject, email string) (*pkgsession.Session, error) {
	if f.sess == nil {
		return nil, nil
	}
	if f.sess.Claims["sub"] == subject && f.sess.Claims["email"] == email {
		return f.sess, nil
	}
	return nil, nil
}
func (f *fakeLookupStore) Get(_ context.Context, _ string) (*pkgsession.Session, error) {
	return nil, nil
}
func (f *fakeLookupStore) Set(_ context.Context, _ string, _ *pkgsession.Session, _ int) error {
	return nil
}
func (f *fakeLookupStore) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeLookupStore) DeleteSessionsBySubjectEmail(ctx context.Context, subject, email string) (int, error) {
	sess, err := f.FindSessionBySubjectEmail(ctx, subject, email)
	if err != nil || sess == nil {
		return 0, err
	}
	if err := f.Delete(ctx, sess.ID); err != nil {
		return 0, err
	}
	return 1, nil
}

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

func TestTokenHandoffUser(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080", CookieName: "test", SessionTTLSeconds: 3600, AdminSecret: "expected-secret"}
	store := &fakeLookupStore{sess: &pkgsession.Session{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresAt:    time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC).Unix(),
		Claims: map[string]any{
			"sub":   "user-123",
			"email": "user@example.com",
		},
	}}
	h := New(&mockAgentService{}, cfg, store, nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "/internal/token-handoff/user", strings.NewReader(`{"lookup":{"subject":"user-123","email":"user@example.com"},"token_use":"peoplespace_user_api"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "expected-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["access_token"] != "access-token" || got["refresh_token"] != "refresh-token" || got["refresh_owner"] != "platform-api" {
		t.Fatalf("unexpected response: %#v", got)
	}
}

func TestRevokeSessionByLookup(t *testing.T) {
	cfg := &config.Config{HTTPPort: "8080", CookieName: "test", SessionTTLSeconds: 3600, AdminSecret: "expected-secret"}
	store := &fakeLookupStore{sess: &pkgsession.Session{
		ID: "sess-1",
		Claims: map[string]any{
			"sub":   "user-123",
			"email": "user@example.com",
		},
	}}
	h := New(&mockAgentService{}, cfg, store, nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "/internal/session/revoke", strings.NewReader(`{"lookup":{"subject":"user-123","email":"user@example.com"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "expected-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if len(store.deleted) != 1 || store.deleted[0] != "sess-1" {
		t.Fatalf("deleted=%v, want [sess-1]", store.deleted)
	}
}
