package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/internal/auth/service"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/pkg/auth"
	"github.com/accessgate/accessgate/pkg/cookie"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
)

type mockAgentService struct{}
type handoffPKCEStore struct{}
type handoffRefreshLock struct{}
type handoffProvider struct{ refreshCalls int }

func (p *handoffProvider) Descriptor() plugin.PluginDescriptor {
	return plugin.PluginDescriptor{ID: "provider:handoff-test", Kind: plugin.PluginKindProvider, Name: "handoff-test"}
}
func (p *handoffProvider) Health(context.Context) plugin.PluginHealth {
	return plugin.PluginHealth{State: plugin.PluginStateHealthy}
}
func (p *handoffProvider) AuthorizationURL(context.Context, string, string, string, map[string]string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (p *handoffProvider) ExchangeCode(context.Context, string, string, string) (*plugin.ProviderTokens, error) {
	return nil, fmt.Errorf("not implemented")
}
func (p *handoffProvider) Refresh(_ context.Context, refreshToken string) (*plugin.ProviderTokens, error) {
	p.refreshCalls++
	return &plugin.ProviderTokens{
		AccessToken:  "access-2",
		RefreshToken: refreshToken,
		ExpiresIn:    3600,
	}, nil
}
func (p *handoffProvider) EndSessionURL(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

type fakeLookupStore struct {
	sess    *pkgsession.Session
	byID    map[string]*pkgsession.Session
	deleted []string
}

func (handoffPKCEStore) Get(context.Context, string) (*pkgsession.PKCEState, error)    { return nil, nil }
func (handoffPKCEStore) Set(context.Context, string, *pkgsession.PKCEState, int) error { return nil }
func (handoffPKCEStore) Delete(context.Context, string) error                          { return nil }
func (handoffRefreshLock) Obtain(context.Context, string, int) (bool, error)           { return true, nil }
func (handoffRefreshLock) Release(context.Context, string) error                       { return nil }

func (f *fakeLookupStore) Ping(_ context.Context) error { return nil }
func (f *fakeLookupStore) FindSessionBySubjectEmail(_ context.Context, subject, email string) (*pkgsession.Session, error) {
	if f.sess == nil && len(f.byID) == 0 {
		return nil, nil
	}
	if f.sess != nil && f.sess.Claims["sub"] == subject && f.sess.Claims["email"] == email {
		return f.sess, nil
	}
	for _, sess := range f.byID {
		if sess != nil && sess.Claims["sub"] == subject && sess.Claims["email"] == email {
			return sess, nil
		}
	}
	return nil, nil
}
func (f *fakeLookupStore) Get(_ context.Context, id string) (*pkgsession.Session, error) {
	if f.byID != nil {
		return f.byID[id], nil
	}
	if f.sess != nil && f.sess.ID == id {
		return f.sess, nil
	}
	return nil, nil
}
func (f *fakeLookupStore) Set(_ context.Context, id string, sess *pkgsession.Session, _ int) error {
	if f.byID == nil {
		f.byID = map[string]*pkgsession.Session{}
	}
	f.byID[id] = sess
	if f.sess != nil && f.sess.ID == id {
		f.sess = sess
	}
	return nil
}
func (f *fakeLookupStore) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	if f.byID != nil {
		delete(f.byID, id)
	}
	if f.sess != nil && f.sess.ID == id {
		f.sess = nil
	}
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

func TestTokenHandoffUserRefreshesNearExpirySession(t *testing.T) {
	cfg := &config.Config{
		OIDCIssuer:          "https://issuer.example",
		OIDCRedirectURI:     "https://app.example.com/callback",
		OIDCClientID:        "client-1",
		RedisURL:            "redis://localhost:6379",
		CookieSigningSecret: "test-cookie-signing-secret-32bytes",
		AppBaseURL:          "https://app.example.com",
		HTTPPort:            "8080",
		CookieName:          "test",
		SessionTTLSeconds:   3600,
		AdminSecret:         "expected-secret",
	}
	cfg.ApplyDefaults()

	store := &fakeLookupStore{byID: map[string]*pkgsession.Session{
		"sess-1": {
			ID:           "sess-1",
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Unix() + int64(cfg.SessionRefreshEarlySeconds/2),
			Claims: map[string]any{
				"sub":   "user-123",
				"email": "user@example.com",
			},
		},
	}}
	prov := &handoffProvider{}
	svc, err := service.New(
		cfg,
		store,
		handoffPKCEStore{},
		handoffRefreshLock{},
		cookie.NewSignedManager(cfg.CookieSigningSecret),
		nil,
		prov,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	h := New(svc, cfg, store, nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "/internal/token-handoff/user", strings.NewReader("{\"lookup\":{\"subject\":\"user-123\",\"email\":\"user@example.com\"},\"token_use\":\"peoplespace_user_api\"}"))
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
	if got["access_token"] != "access-2" {
		t.Fatalf("access_token = %#v, want access-2", got["access_token"])
	}
	if prov.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", prov.refreshCalls)
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
