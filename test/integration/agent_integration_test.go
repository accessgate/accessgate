// Package integration runs integration tests for the agent (mock IdP, in-memory stores).
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	"github.com/ArmanAvanesyan/accessgate/internal/auth/httpserver"
	"github.com/ArmanAvanesyan/accessgate/internal/auth/service"
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/internal/plugins/register"
	"github.com/ArmanAvanesyan/accessgate/pkg/auth"
	"github.com/ArmanAvanesyan/accessgate/pkg/cookie"
	pkgsession "github.com/ArmanAvanesyan/accessgate/pkg/session"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
	"github.com/golang-jwt/jwt/v5"
)

// inMemorySessionStore implements session.SessionStore for tests.
type inMemorySessionStore struct {
	mu   sync.RWMutex
	data map[string]*pkgsession.Session
}

func newInMemorySessionStore() *inMemorySessionStore {
	return &inMemorySessionStore{data: make(map[string]*pkgsession.Session)}
}

func (s *inMemorySessionStore) Get(ctx context.Context, id string) (*pkgsession.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess, ok := s.data[id]; ok {
		return sess, nil
	}
	return nil, nil
}

func (s *inMemorySessionStore) Set(ctx context.Context, id string, sess *pkgsession.Session, ttlSeconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = sess
	return nil
}

func (s *inMemorySessionStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

type inMemoryPKCEStore struct {
	mu   sync.RWMutex
	data map[string]*pkgsession.PKCEState
}

func newInMemoryPKCEStore() *inMemoryPKCEStore {
	return &inMemoryPKCEStore{data: make(map[string]*pkgsession.PKCEState)}
}

func (s *inMemoryPKCEStore) Get(ctx context.Context, state string) (*pkgsession.PKCEState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.data[state]; ok {
		return p, nil
	}
	return nil, nil
}

func (s *inMemoryPKCEStore) Set(ctx context.Context, state string, p *pkgsession.PKCEState, ttlSeconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = p
	return nil
}

func (s *inMemoryPKCEStore) Delete(ctx context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, state)
	return nil
}

type inMemoryRefreshLockStore struct {
	mu   sync.Mutex
	held map[string]struct{}
}

func newInMemoryRefreshLockStore() *inMemoryRefreshLockStore {
	return &inMemoryRefreshLockStore{held: make(map[string]struct{})}
}

func (s *inMemoryRefreshLockStore) Obtain(ctx context.Context, sessionID string, ttlSeconds int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.held[sessionID]; ok {
		return false, nil
	}
	s.held[sessionID] = struct{}{}
	return true, nil
}

func (s *inMemoryRefreshLockStore) Release(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.held, sessionID)
	return nil
}

// mockOIDCServer starts an httptest server that acts as OIDC IdP: discovery, /auth (stores state->nonce, redirects to app), /token (returns signed ID token), /keys (JWKS).
// Issuer in discovery and in the signed ID token is derived from r.Host so it matches the server URL.
func mockOIDCServer(t *testing.T, _, redirectURI, audience string, priv *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	stateToNonce := make(map[string]string)
	var stateMu sync.Mutex

	jwksBytes := mustJWKS(t, priv)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		base := "http://" + r.Host
		if r.TLS != nil {
			base = "https://" + r.Host
		}
		doc := map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/keys",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		nonce := r.URL.Query().Get("nonce")
		if state != "" && nonce != "" {
			stateMu.Lock()
			stateToNonce[state] = nonce
			stateMu.Unlock()
		}
		redirect := redirectURI + "?code=" + url.QueryEscape(state) + "&state=" + url.QueryEscape(state)
		http.Redirect(w, r, redirect, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		code := r.FormValue("code")
		stateMu.Lock()
		nonce := stateToNonce[code]
		stateMu.Unlock()
		if nonce == "" {
			nonce = "fallback"
		}
		// Use request Host so issuer matches what discovery returned (and what agent uses for JWKS lookup).
		issuer := "http://" + r.Host
		if r.TLS != nil {
			issuer = "https://" + r.Host
		}
		idToken, err := signIDToken(priv, issuer, audience, "test-user", nonce, time.Now().Add(time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at",
			"refresh_token": "rt",
			"id_token":      idToken,
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})

	return httptest.NewServer(mux)
}

func signIDToken(priv *rsa.PrivateKey, issuer, audience, sub, nonce string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": sub, "exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "rsa1"
	return tok.SignedString(priv)
}

func mustJWKS(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{"kid": "rsa1", "kty": "RSA", "n": n, "e": e},
		},
	}
	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAgent_LoginRedirect(t *testing.T) {
	cfg, mockSrv, jwksSource, svc := setupAgentService(t)
	defer mockSrv.Close()
	srv := httpserver.New(svc, cfg, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /login: status %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc == "" || !strings.HasPrefix(loc, mockSrv.URL) {
		t.Errorf("redirect Location: %s", loc)
	}
	_ = jwksSource
}

func TestAgent_LoginCallback_Session_Refresh_Logout(t *testing.T) {
	cfg, mockSrv, _, svc := setupAgentService(t)
	defer mockSrv.Close()
	srv := httpserver.New(svc, cfg, nil, nil)

	// 1. Login start
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /login: %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	parsed, _ := url.Parse(loc)
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %s", loc)
	}

	// 2. Simulate IdP redirect: GET mock /auth so it stores state->nonce, then get redirect to callback
	authReq := httptest.NewRequest(http.MethodGet, loc, nil)
	authRR := httptest.NewRecorder()
	mockSrv.Config.Handler.ServeHTTP(authRR, authReq)
	if authRR.Code != http.StatusFound {
		t.Fatalf("mock /auth: %d", authRR.Code)
	}
	callbackURL := authRR.Header().Get("Location")
	// 3. Call agent callback with code and state from IdP redirect
	req = httptest.NewRequest(http.MethodGet, callbackURL, nil)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /callback: %d, body: %s", rr.Code, rr.Body.String())
	}
	setCookie := rr.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("expected Set-Cookie after callback")
	}
	cookieVal := parseCookieValue(setCookie, cfg.CookieName)
	if cookieVal == "" {
		t.Fatalf("parse cookie from %s", setCookie)
	}

	// 4. Session
	req = httptest.NewRequest(http.MethodGet, "/session", nil)
	req.Header.Set("Cookie", cfg.CookieName+"="+cookieVal)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /session: %d", rr.Code)
	}
	var sessionResp struct {
		IsAuthenticated bool `json:"is_authenticated"`
		User            *struct {
			Sub string `json:"sub"`
		} `json:"user"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&sessionResp); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if !sessionResp.IsAuthenticated || sessionResp.User == nil || sessionResp.User.Sub != "test-user" {
		t.Errorf("session: is_authenticated=%v user=%+v", sessionResp.IsAuthenticated, sessionResp.User)
	}

	// 5. Refresh
	req = httptest.NewRequest(http.MethodGet, "/refresh", nil)
	req.Header.Set("Cookie", cfg.CookieName+"="+cookieVal)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /refresh: %d", rr.Code)
	}

	// 6. Logout
	req = httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Cookie", cfg.CookieName+"="+cookieVal)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /logout: %d", rr.Code)
	}
}

func parseCookieValue(setCookie, name string) string {
	for _, part := range strings.Split(setCookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+"=") {
			return strings.TrimPrefix(part, name+"=")
		}
	}
	return ""
}

func setupAgentService(t *testing.T) (*config.Config, *httptest.Server, token.JWKSSource, auth.Service) {
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

	// Create/configure provider plugin so agent service can use it for auth flows.
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
	return cfg, mockSrv, jwksSource, svc
}

type staticJWKSSource struct {
	jwks map[string][]byte
}

func (s *staticJWKSSource) GetJWKS(ctx context.Context, issuer string) ([]byte, error) {
	if b, ok := s.jwks[issuer]; ok {
		return b, nil
	}
	return nil, nil
}
