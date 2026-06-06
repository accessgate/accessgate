// Package integration: auth/service edge-case integration tests covering
// PKCE/state mismatch on the login callback and refresh-lock contention.
//
// These complement agent_integration_test.go (happy-path lifecycle) and reuse
// the same hermetic harness: a mock OIDC IdP on loopback and in-memory
// session/PKCE/refresh-lock stores. No external Redis or network is required.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/internal/auth/service"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/plugins/register"
	"github.com/accessgate/accessgate/pkg/auth"
	"github.com/accessgate/accessgate/pkg/cookie"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
)

// authHarness bundles the service under test with the concrete in-memory stores
// and cookie manager, so tests can seed sessions / pre-acquire locks directly.
type authHarness struct {
	cfg         *config.Config
	svc         auth.Service
	sessions    *inMemorySessionStore
	pkce        *inMemoryPKCEStore
	refreshLock *inMemoryRefreshLockStore
	cookie      cookie.Manager
	closeFn     func()
}

// setupAuthHarness mirrors setupAgentService but exposes the stores/cookie
// manager and a *service.Service handle for white-box edge testing.
func setupAuthHarness(t *testing.T) *authHarness {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	mockSrv := mockOIDCServer(t, "", "https://app.example.com/callback", "test-client", priv)
	issuer := mockSrv.URL
	jwksBytes := mustJWKS(t, priv)
	jwksSource := &staticJWKSSource{jwks: map[string][]byte{issuer: jwksBytes}}

	cfg := &config.Config{
		OIDCIssuer:                   issuer,
		OIDCRedirectURI:              "https://app.example.com/callback",
		OIDCClientID:                 "test-client",
		OIDCClientSecret:             "secret",
		RedisURL:                     "redis://localhost:6379",
		SessionRedisPrefix:           "auth",
		SessionTTLSeconds:            3600,
		SessionPKCETTLSeconds:        300,
		SessionRefreshLockTTLSeconds: 15,
		SessionRefreshEarlySeconds:   60,
		CookieSigningSecret:          "test-cookie-secret-32-bytes-long!!",
		AppBaseURL:                   "https://app.example.com",
		LoginErrorRedirectPath:       "/login?error=oidc_error",
		HTTPPort:                     "8080",
		CookieName:                   "test_session",
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	sessions := newInMemorySessionStore()
	pkce := newInMemoryPKCEStore()
	refreshLock := newInMemoryRefreshLockStore()
	cookieManager := cookie.NewSignedManager(cfg.CookieSigningSecret)

	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(context.Background(), reg); err != nil {
		t.Fatalf("register builtins: %v", err)
	}
	regEntry, ok := reg.RegistrationFor(plugin.PluginID("provider:oidc"))
	if !ok || regEntry == nil {
		t.Fatalf("provider:oidc not registered")
	}
	p, err := regEntry.Factory(context.Background(), regEntry.Descriptor)
	if err != nil {
		t.Fatalf("provider factory: %v", err)
	}
	cp, ok := p.(plugin.ConfigurablePlugin)
	if !ok {
		t.Fatalf("provider does not implement ConfigurablePlugin")
	}
	providerCfg := map[string]any{
		"issuer":        cfg.OIDCIssuer,
		"client_id":     cfg.OIDCClientID,
		"client_secret": cfg.OIDCClientSecret,
		"redirect_uri":  cfg.OIDCRedirectURI,
		"scopes":        cfg.OIDCScopesSlice(),
		"claims_source": cfg.OIDCClaimsSource,
		"audience":      cfg.OIDCAudience,
	}
	if err := cp.Configure(context.Background(), providerCfg); err != nil {
		t.Fatalf("provider Configure: %v", err)
	}
	provider, ok := p.(plugin.ProviderPlugin)
	if !ok {
		t.Fatalf("provider does not implement ProviderPlugin")
	}

	svc, err := service.New(cfg, sessions, pkce, refreshLock, cookieManager, jwksSource, provider, nil, nil)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	return &authHarness{
		cfg:         cfg,
		svc:         svc,
		sessions:    sessions,
		pkce:        pkce,
		refreshLock: refreshLock,
		cookie:      cookieManager,
		closeFn:     mockSrv.Close,
	}
}

// TestAuth_LoginEnd_StateMismatch_RedirectsToError verifies that a callback
// whose state has no matching PKCE entry (forged/expired/replayed state) is
// rejected: the user is sent to the login error path and the cookie is cleared,
// and no session is created.
func TestAuth_LoginEnd_StateMismatch_RedirectsToError(t *testing.T) {
	h := setupAuthHarness(t)
	defer h.closeFn()

	resp, err := h.svc.LoginEnd(context.Background(), auth.LoginEndRequest{
		Code:  "some-code",
		State: "state-that-was-never-stored",
		Host:  "app.example.com",
	})
	if err != nil {
		t.Fatalf("LoginEnd: %v", err)
	}
	wantPrefix := h.cfg.AppBaseURL + h.cfg.LoginErrorRedirectPath
	if !strings.HasPrefix(resp.RedirectURL, wantPrefix) {
		t.Errorf("expected redirect to error path %q, got %q", wantPrefix, resp.RedirectURL)
	}
	if !resp.ClearCookie {
		t.Error("expected ClearCookie=true on state mismatch")
	}
	if resp.SetCookieValue != "" {
		t.Error("expected no session cookie to be set on state mismatch")
	}
	if len(h.sessions.data) != 0 {
		t.Errorf("expected no session created on state mismatch, got %d", len(h.sessions.data))
	}
}

// TestAuth_LoginEnd_MissingStateOrCode_RedirectsToError covers the guard for an
// empty state or code (malformed callback) — also a redirect to error.
func TestAuth_LoginEnd_MissingStateOrCode_RedirectsToError(t *testing.T) {
	h := setupAuthHarness(t)
	defer h.closeFn()

	cases := []auth.LoginEndRequest{
		{Code: "", State: "s", Host: "app.example.com"},
		{Code: "c", State: "", Host: "app.example.com"},
		{Error: "access_denied", Host: "app.example.com"},
	}
	for _, req := range cases {
		resp, err := h.svc.LoginEnd(context.Background(), req)
		if err != nil {
			t.Fatalf("LoginEnd(%+v): %v", req, err)
		}
		if !strings.HasPrefix(resp.RedirectURL, h.cfg.AppBaseURL+h.cfg.LoginErrorRedirectPath) {
			t.Errorf("LoginEnd(%+v): redirect=%q, want error path", req, resp.RedirectURL)
		}
		if !resp.ClearCookie {
			t.Errorf("LoginEnd(%+v): expected ClearCookie", req)
		}
	}
}

// TestAuth_Refresh_LockHeld_SkipsRefresh verifies the refresh-lock behavior:
// when another worker already holds the per-session refresh lock, Refresh must
// NOT call the IdP or rotate tokens — it returns a no-op response and leaves
// the access token unchanged.
func TestAuth_Refresh_LockHeld_SkipsRefresh(t *testing.T) {
	h := setupAuthHarness(t)
	defer h.closeFn()

	const sessionID = "sess-refresh-lock"
	// Seed a session that is within the refresh window so Refresh attempts a refresh.
	sess := &pkgsession.Session{
		ID:           sessionID,
		AccessToken:  "old-access-token",
		RefreshToken: "rt-original",
		ExpiresAt:    time.Now().Add(5 * time.Second).Unix(), // < SessionRefreshEarlySeconds=60 -> NeedsRefresh
		Claims:       map[string]any{"sub": "test-user"},
	}
	if err := h.sessions.Set(context.Background(), sessionID, sess, h.cfg.SessionTTLSeconds); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// Pre-acquire the refresh lock to simulate a concurrent refresh in flight.
	ok, err := h.refreshLock.Obtain(context.Background(), sessionID, h.cfg.SessionRefreshLockTTLSeconds)
	if err != nil || !ok {
		t.Fatalf("pre-acquire lock: ok=%v err=%v", ok, err)
	}

	cookieVal, err := h.cookie.Encode(sessionID)
	if err != nil {
		t.Fatalf("cookie encode: %v", err)
	}

	resp, err := h.svc.Refresh(context.Background(), auth.RefreshRequest{SessionCookie: cookieVal})
	if err != nil {
		t.Fatalf("Refresh under held lock should be a no-op, got err: %v", err)
	}
	if resp.Refreshed {
		t.Error("expected Refreshed=false when lock is held by another worker")
	}
	if resp.SetCookieValue != "" {
		t.Error("expected no new cookie when refresh was skipped")
	}

	// The stored session must be untouched (no token rotation occurred).
	stored, _ := h.sessions.Get(context.Background(), sessionID)
	if stored == nil || stored.AccessToken != "old-access-token" || stored.RefreshToken != "rt-original" {
		t.Errorf("session tokens must be unchanged when refresh skipped: %+v", stored)
	}
}

// TestAuth_Refresh_NotDue_SkipsRefresh verifies that a session well outside the
// early-refresh window is left alone (no lock contention, no IdP call).
func TestAuth_Refresh_NotDue_SkipsRefresh(t *testing.T) {
	h := setupAuthHarness(t)
	defer h.closeFn()

	const sessionID = "sess-not-due"
	sess := &pkgsession.Session{
		ID:           sessionID,
		AccessToken:  "fresh-access-token",
		RefreshToken: "rt-fresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(), // far outside the 60s window
		Claims:       map[string]any{"sub": "test-user"},
	}
	if err := h.sessions.Set(context.Background(), sessionID, sess, h.cfg.SessionTTLSeconds); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	cookieVal, err := h.cookie.Encode(sessionID)
	if err != nil {
		t.Fatalf("cookie encode: %v", err)
	}

	resp, err := h.svc.Refresh(context.Background(), auth.RefreshRequest{SessionCookie: cookieVal})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if resp.Refreshed {
		t.Error("expected no refresh when token is not near expiry")
	}
	// Lock must not be left held.
	gotLock, _ := h.refreshLock.Obtain(context.Background(), sessionID, h.cfg.SessionRefreshLockTTLSeconds)
	if !gotLock {
		t.Error("refresh lock should be free after a not-due refresh")
	}
}
