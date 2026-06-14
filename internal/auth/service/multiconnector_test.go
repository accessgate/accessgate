package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/pkg/auth"
	"github.com/accessgate/accessgate/pkg/cookie"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
	"github.com/accessgate/accessgate/pkg/token"
)

type fakeFinder struct{ sess *pkgsession.Session }

func (f *fakeFinder) FindSessionBySubjectEmail(_ context.Context, subject, email string) (*pkgsession.Session, error) {
	if f.sess != nil && f.sess.Claims["sub"] == subject && f.sess.Claims["email"] == email {
		return f.sess, nil
	}
	return nil, nil
}

type fakeOnce struct{ seen map[string]bool }

func (f *fakeOnce) ConsumeOnce(_ context.Context, key string, _ time.Duration) (bool, error) {
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

func TestClaimToString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"abc", "abc"},
		{float64(123456789), "123456789"},
		{json.Number("987654321"), "987654321"},
		{int64(42), "42"},
		{int(7), "7"},
		{nil, ""},
		{map[string]any{}, ""},
	}
	for _, tc := range cases {
		if got := claimToString(tc.in); got != tc.want {
			t.Errorf("claimToString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAuthoritativeID(t *testing.T) {
	s := &Service{}
	subConn := &connector{cfg: config.ConnectorConfig{ClaimMapping: config.ClaimMappingConfig{AuthoritativeIDClaim: "sub"}}}
	if got := s.authoritativeID(subConn, map[string]any{"sub": "oidc-1", "tg_id": float64(555)}); got != "" {
		t.Errorf("sub-mapped connector should return empty (use principal.Subject), got %q", got)
	}
	tgConn := &connector{cfg: config.ConnectorConfig{ClaimMapping: config.ClaimMappingConfig{AuthoritativeIDClaim: "tg_id", IDKind: "telegram_id"}}}
	if got := s.authoritativeID(tgConn, map[string]any{"sub": "oidc-1", "tg_id": float64(555)}); got != "555" {
		t.Errorf("telegram connector should map tg_id numeric -> %q, got %q", "555", got)
	}
	if got := s.authoritativeID(tgConn, map[string]any{"sub": "oidc-1"}); got != "" {
		t.Errorf("missing authoritative claim should return empty, got %q", got)
	}
}

func TestApplyRefreshedClaims_PreservesTelegramID(t *testing.T) {
	s := &Service{}
	tgConn := &connector{cfg: config.ConnectorConfig{ClaimMapping: config.ClaimMappingConfig{AuthoritativeIDClaim: "tg_id", IDKind: "telegram_id"}}}
	sess := &pkgsession.Session{Claims: map[string]any{"sub": "555", "authoritative_id_kind": "telegram_id"}}
	// Refreshed token carries only the OIDC sub (no tg_id) — the established id must survive.
	s.applyRefreshedClaims(tgConn, sess, map[string]any{"sub": "oidc-internal"})
	if sess.Claims["sub"] != "555" {
		t.Errorf("refreshed sub = %v, want preserved 555", sess.Claims["sub"])
	}
	if sess.Claims["authoritative_id_kind"] != "telegram_id" {
		t.Errorf("id_kind = %v, want telegram_id", sess.Claims["authoritative_id_kind"])
	}
	// Refreshed token that DOES carry tg_id updates the id.
	s.applyRefreshedClaims(tgConn, sess, map[string]any{"sub": "oidc-internal", "tg_id": float64(777)})
	if sess.Claims["sub"] != "777" {
		t.Errorf("refreshed sub = %v, want updated 777", sess.Claims["sub"])
	}
}

func newMultiConnectorConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{
		RedisURL:            "redis://localhost:6379",
		CookieSigningSecret: "test-cookie-signing-secret-32bytes",
		AppBaseURL:          "https://app.example.com",
		HTTPPort:            "8080",
		Connectors: []config.ConnectorConfig{
			{ID: "sso", Default: true, OIDCIssuer: "https://sso", OIDCRedirectURI: "https://app.example.com/callback/sso", OIDCClientID: "sso-client"},
			{ID: "telegram", OIDCIssuer: "https://tg", OIDCRedirectURI: "https://app.example.com/callback/telegram", OIDCClientID: "tg-client",
				ClaimMapping: config.ClaimMappingConfig{AuthoritativeIDClaim: "tg_id", IDKind: "telegram_id"}},
		},
	}
	cfg.ApplyDefaults()
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}
	return cfg
}

func TestMultiConnector_LoginStartRoutesToConnector(t *testing.T) {
	ctx := context.Background()
	cfg := newMultiConnectorConfig(t)

	ssoProv := &mockProvider{}
	tgProv := &mockProvider{}
	ssoPKCE := newInMemoryPKCEStore()
	tgPKCE := newInMemoryPKCEStore()

	conns := []Connector{
		{Config: cfg.Connectors[0], Provider: ssoProv, Sessions: newInMemorySessionStore(), PKCE: ssoPKCE, RefreshLock: &inMemoryRefreshLockStore{}},
		{Config: cfg.Connectors[1], Provider: tgProv, Sessions: newInMemorySessionStore(), PKCE: tgPKCE, RefreshLock: &inMemoryRefreshLockStore{}},
	}
	svc, err := NewMultiConnector(cfg, conns, cookie.NewSignedManager(cfg.CookieSigningSecret), token.JWKSSource(nil), nil, nil)
	if err != nil {
		t.Fatalf("NewMultiConnector: %v", err)
	}

	// Telegram login must hit the telegram provider and store PKCE in the telegram namespace.
	if _, err := svc.LoginStart(ctx, auth.LoginStartRequest{Connector: "telegram", RedirectTo: "/"}); err != nil {
		t.Fatalf("LoginStart telegram: %v", err)
	}
	if tgProv.authCalls != 1 || ssoProv.authCalls != 0 {
		t.Fatalf("expected telegram provider call only; sso=%d tg=%d", ssoProv.authCalls, tgProv.authCalls)
	}
	if len(tgPKCE.data) != 1 || len(ssoPKCE.data) != 0 {
		t.Fatalf("PKCE should be namespaced to telegram store; sso=%d tg=%d", len(ssoPKCE.data), len(tgPKCE.data))
	}

	// Empty connector resolves to the default (sso).
	if _, err := svc.LoginStart(ctx, auth.LoginStartRequest{Connector: "", RedirectTo: "/"}); err != nil {
		t.Fatalf("LoginStart default: %v", err)
	}
	if ssoProv.authCalls != 1 {
		t.Fatalf("expected default to route to sso, got sso=%d", ssoProv.authCalls)
	}

	// Unknown connector is an error.
	if _, err := svc.LoginStart(ctx, auth.LoginStartRequest{Connector: "nope"}); err == nil {
		t.Fatal("expected error for unknown connector")
	}

	// Per-connector cookie names.
	if got := svc.ConnectorCookieName("telegram"); got != "__Host-ess_session_telegram" {
		t.Errorf("telegram cookie name = %q", got)
	}
	if got := svc.ConnectorCookieName(""); got != "__Host-ess_session" {
		t.Errorf("default cookie name = %q", got)
	}
}

func TestHandoff_IssueAndRedeem(t *testing.T) {
	ctx := context.Background()
	cfg := newMultiConnectorConfig(t)

	tgSessions := newInMemorySessionStore()
	tgSessions.data["sess-tg"] = &pkgsession.Session{ID: "sess-tg", Claims: map[string]any{"sub": "555", "email": "u@example.com"}}
	finder := &fakeFinder{sess: tgSessions.data["sess-tg"]}

	cm := cookie.NewSignedManager(cfg.CookieSigningSecret)
	conns := []Connector{
		{Config: cfg.Connectors[0], Provider: &mockProvider{}, Sessions: newInMemorySessionStore(), PKCE: newInMemoryPKCEStore(), RefreshLock: &inMemoryRefreshLockStore{}},
		{Config: cfg.Connectors[1], Provider: &mockProvider{}, Sessions: tgSessions, PKCE: newInMemoryPKCEStore(), RefreshLock: &inMemoryRefreshLockStore{}, Finder: finder},
	}
	svc, err := NewMultiConnector(cfg, conns, cm, token.JWKSSource(nil), nil, nil)
	if err != nil {
		t.Fatalf("NewMultiConnector: %v", err)
	}
	svc.EnableHandoff(&fakeOnce{}, 60)

	ticket, err := svc.IssueHandoff(ctx, "telegram", "555", "u@example.com")
	if err != nil {
		t.Fatalf("IssueHandoff: %v", err)
	}
	cookieValue, connector, err := svc.RedeemHandoff(ctx, "telegram", ticket)
	if err != nil {
		t.Fatalf("RedeemHandoff: %v", err)
	}
	if connector != "telegram" {
		t.Errorf("redeemed connector = %q, want telegram", connector)
	}
	// The cookie must decode to the telegram session ref.
	var sessID string
	if err := cm.Decode(cookieValue, &sessID); err != nil {
		t.Fatalf("decode handoff cookie: %v", err)
	}
	if sessID != "sess-tg" {
		t.Errorf("handoff cookie session = %q, want sess-tg", sessID)
	}
	// Second redemption must fail (one-time).
	if _, _, err := svc.RedeemHandoff(ctx, "telegram", ticket); err == nil {
		t.Fatal("expected replay rejection on second redeem")
	}
	// Connector mismatch must be rejected.
	ticket2, _ := svc.IssueHandoff(ctx, "telegram", "555", "u@example.com")
	if _, _, err := svc.RedeemHandoff(ctx, "sso", ticket2); err == nil {
		t.Fatal("expected connector mismatch rejection")
	}
}
