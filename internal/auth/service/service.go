package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/pkg/auth"
	"github.com/ArmanAvanesyan/accessgate/pkg/cookie"
	"github.com/ArmanAvanesyan/accessgate/pkg/observability"
	"github.com/ArmanAvanesyan/accessgate/pkg/oidc"
	pkgsdk "github.com/ArmanAvanesyan/accessgate/pkg/sdk"
	pkgsession "github.com/ArmanAvanesyan/accessgate/pkg/session"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

// Service implements auth.Service.
type Service struct {
	cfg           *config.Config
	provider      plugin.ProviderPlugin
	jwks          token.JWKSSource
	sessions      pkgsession.SessionStore
	pkce          pkgsession.PKCEStore
	refreshLock   pkgsession.RefreshLockStore
	cookie        cookie.Manager
	cookieOpts    cookie.CookieOptions
	tracer        observability.Tracer
	metrics       observability.Metrics
	logger        *log.Logger
	webhookClient *http.Client
}

// New creates an accessgate-auth Service.
func New(
	cfg *config.Config,
	sessions pkgsession.SessionStore,
	pkce pkgsession.PKCEStore,
	refreshLock pkgsession.RefreshLockStore,
	cookieManager cookie.Manager,
	jwks token.JWKSSource,
	provider plugin.ProviderPlugin,
	tracer observability.Tracer,
	metrics observability.Metrics,
) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	opts := cookie.CookieOptions{
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Secure:   bool(cfg.CookieSecure),
		HTTPOnly: true,
		SameSite: cfg.CookieSameSite,
		MaxAge:   cfg.SessionTTLSeconds,
	}
	if tracer == nil {
		tracer = observability.NopTracer{}
	}
	if metrics == nil {
		metrics = observability.NopMetrics{}
	}
	return &Service{
		cfg:           cfg,
		provider:      provider,
		jwks:          jwks,
		sessions:      sessions,
		pkce:          pkce,
		refreshLock:   refreshLock,
		cookie:        cookieManager,
		cookieOpts:    opts,
		tracer:        tracer,
		metrics:       metrics,
		logger:        log.New(log.Writer(), "[accessgate-auth] ", log.LstdFlags|log.LUTC),
		webhookClient: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// NewWithRuntimeStoreProvider creates an accessgate-auth Service from the runtime store seam.
func NewWithRuntimeStoreProvider(
	cfg *config.Config,
	stores pkgsession.RuntimeStoreProvider,
	cookieManager cookie.Manager,
	jwks token.JWKSSource,
	provider plugin.ProviderPlugin,
	tracer observability.Tracer,
	metrics observability.Metrics,
) (*Service, error) {
	if stores == nil {
		return nil, fmt.Errorf("runtime stores are required")
	}
	return New(
		cfg,
		stores.SessionStore(),
		stores.PKCEStore(),
		stores.RefreshLockStore(),
		cookieManager,
		jwks,
		provider,
		tracer,
		metrics,
	)
}

// Session implements auth.Service.
func (s *Service) Session(ctx context.Context, req auth.SessionRequest) (*auth.SessionResponse, error) {
	if req.SessionCookie == "" {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	var sessionID string
	if err := s.cookie.Decode(req.SessionCookie, &sessionID); err != nil {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	user := sessionToUser(sess)
	return &auth.SessionResponse{
		IsAuthenticated: true,
		User:            user,
	}, nil
}

// LoginStart implements auth.Service.
func (s *Service) LoginStart(ctx context.Context, req auth.LoginStartRequest) (*auth.LoginStartResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.login_start", "redirect_to", req.RedirectTo)
	defer span.End()
	s.metrics.LoginStarted()

	redirectTo := ValidateRedirect(req.RedirectTo, s.cfg.AppBaseURL, s.cfg.AllowedRedirectOrigins, s.cfg.AllowedRedirectPaths)
	if redirectTo == "" && req.RedirectTo != "" {
		redirectTo = s.cfg.AppBaseURL
	}
	if redirectTo == "" {
		redirectTo = s.cfg.AppBaseURL
	}
	_, pkceSpan := s.tracer.StartSpan(ctx, "auth.pkce_generate")
	verifier, challenge, nonce, err := oidc.GeneratePKCE()
	if err != nil {
		pkceSpan.End()
		return nil, err
	}
	state, err := oidc.GenerateState()
	if err != nil {
		pkceSpan.End()
		return nil, err
	}
	pkceSpan.End()
	_, pkceStoreSpan := s.tracer.StartSpan(ctx, "auth.pkce_store_set")
	err = s.pkce.Set(ctx, state, &pkgsession.PKCEState{
		State:         state,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Nonce:         nonce,
		RedirectTo:    redirectTo,
	}, s.cfg.SessionPKCETTLSeconds)
	if err != nil {
		pkceStoreSpan.End()
		return nil, err
	}
	pkceStoreSpan.End()
	_, authURLSpan := s.tracer.StartSpan(ctx, "auth.oidc_authorization_url")
	var extraParams map[string]string
	if prompt := strings.TrimSpace(req.Prompt); prompt != "" {
		extraParams = map[string]string{"prompt": prompt}
	}
	authURL, err := s.provider.AuthorizationURL(ctx, state, challenge, nonce, extraParams)
	if err != nil {
		authURLSpan.End()
		return nil, err
	}
	authURLSpan.End()
	return &auth.LoginStartResponse{RedirectURL: authURL}, nil
}

// LoginEnd implements auth.Service.
func (s *Service) LoginEnd(ctx context.Context, req auth.LoginEndRequest) (*auth.LoginEndResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.login_end", "state_present", req.State != "", "code_present", req.Code != "")
	defer span.End()
	success := false
	defer func() { s.metrics.LoginCompleted(success) }()

	if req.Error != "" {
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	if req.State == "" || req.Code == "" {
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	_, pkceGetSpan := s.tracer.StartSpan(ctx, "auth.pkce_get")
	p, err := s.pkce.Get(ctx, req.State)
	if err != nil || p == nil {
		pkceGetSpan.End()
		s.logger.Printf("audit: login_end pkce_miss host=%s", req.Host)
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	pkceGetSpan.End()
	_ = s.pkce.Delete(ctx, req.State)
	_, exchangeSpan := s.tracer.StartSpan(ctx, "auth.oidc_exchange_code")
	tr, err := s.provider.ExchangeCode(ctx, req.Code, p.CodeVerifier, s.cfg.OIDCRedirectURI)
	if err != nil {
		exchangeSpan.End()
		s.logger.Printf("audit: login_end exchange_failed host=%s", req.Host)
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	exchangeSpan.End()
	audience := s.cfg.OIDCAudience
	if audience == "" {
		audience = s.cfg.OIDCClientID
	}
	_, validateSpan := s.tracer.StartSpan(ctx, "auth.token_validate_id_token")
	principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, s.cfg.OIDCIssuer, audience, p.Nonce)
	if err != nil {
		validateSpan.End()
		s.logger.Printf("audit: login_end token_invalid host=%s reason=%v", req.Host, err)
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	validateSpan.End()
	expiresAt := time.Now().Unix() + int64(tr.ExpiresIn)
	if tr.ExpiresIn <= 0 {
		s.logger.Printf("warn: IdP omitted expires_in for subject=%s, defaulting to 1 hour", principal.Subject)
		expiresAt = time.Now().Add(1 * time.Hour).Unix()
	}
	claims := principal.Claims
	if claims == nil {
		claims = make(map[string]any)
	}
	claims["sub"] = principal.Subject
	if principal.Roles != nil {
		claims["roles"] = principal.Roles
	}
	sessID, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	sess := &pkgsession.Session{
		ID:           sessID,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresAt:    expiresAt,
		Claims:       claims,
	}
	_, sessionSetSpan := s.tracer.StartSpan(ctx, "auth.session_store_set")
	err = s.sessions.Set(ctx, sessID, sess, s.cfg.SessionTTLSeconds)
	if err != nil {
		sessionSetSpan.End()
		return nil, err
	}
	sessionSetSpan.End()
	s.logger.Printf("audit: login_success subject=%s session_id=%s host=%s", principal.Subject, sessID, req.Host)
	if s.cfg.PostLoginWebhookURL != "" {
		if err := s.callPostLoginWebhook(ctx, s.cfg.PostLoginWebhookURL, sessID, principal.Subject, getClaimString(claims, "email"), claims, req.Host); err != nil {
			s.logger.Printf("warn: post_login_webhook failed: %v", err)
		}
	}
	_, cookieEncodeSpan := s.tracer.StartSpan(ctx, "auth.cookie_encode_session_id")
	cookieValue, err := s.cookie.Encode(sessID)
	if err != nil {
		cookieEncodeSpan.End()
		return nil, err
	}
	cookieEncodeSpan.End()
	redirectURL := ValidateRedirect(p.RedirectTo, s.cfg.AppBaseURL, s.cfg.AllowedRedirectOrigins, s.cfg.AllowedRedirectPaths)
	if redirectURL == "" {
		redirectURL = s.cfg.AppBaseURL
	}
	success = true
	return &auth.LoginEndResponse{
		RedirectURL:    redirectURL,
		SetCookieValue: cookieValue,
	}, nil
}

func getClaimString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func (s *Service) callPostLoginWebhook(ctx context.Context, webhookURL, sessionID, subject, email string, claims map[string]any, host string) error {
	// Validate: only https scheme allowed.
	u, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("webhook: invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook: URL scheme %q not allowed (must be https)", u.Scheme)
	}

	body := map[string]any{
		"session_id": sessionID,
		"subject":    subject,
		"email":      email,
		"claims":     claims,
		"host":       host,
	}
	data, _ := json.Marshal(body)

	// HMAC-SHA256 signature so the receiver can verify the payload origin.
	mac := hmac.New(sha256.New, []byte(s.cfg.CookieSigningSecret))
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AccessGate-Signature", "sha256="+sig)

	resp, err := s.webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// Refresh implements auth.Service.
func (s *Service) Refresh(ctx context.Context, req auth.RefreshRequest) (*auth.RefreshResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.refresh")
	defer span.End()
	success := false
	defer func() { s.metrics.RefreshCompleted(success) }()

	if req.SessionCookie == "" {
		return nil, fmt.Errorf("no session cookie")
	}
	var sessionID string
	if err := s.cookie.Decode(req.SessionCookie, &sessionID); err != nil {
		return nil, fmt.Errorf("invalid cookie")
	}
	_, sessionGetSpan := s.tracer.StartSpan(ctx, "auth.session_store_get")
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		sessionGetSpan.End()
		return nil, fmt.Errorf("session not found")
	}
	sessionGetSpan.End()
	if sess.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token")
	}
	now := time.Now()
	if !sess.NeedsRefresh(now, s.cfg.SessionRefreshEarlySeconds) {
		return &auth.RefreshResponse{}, nil
	}
	_, lockSpan := s.tracer.StartSpan(ctx, "auth.refresh_lock_obtain")
	ok, err := s.refreshLock.Obtain(ctx, sessionID, s.cfg.SessionRefreshLockTTLSeconds)
	if err != nil || !ok {
		lockSpan.End()
		return &auth.RefreshResponse{}, nil
	}
	lockSpan.End()
	defer func() { _ = s.refreshLock.Release(ctx, sessionID) }()
	_, providerRefreshSpan := s.tracer.StartSpan(ctx, "auth.oidc_refresh")
	tr, err := s.provider.Refresh(ctx, sess.RefreshToken)
	if err != nil {
		providerRefreshSpan.End()
		s.logger.Printf("audit: refresh_failed session_id=%s reason=%v", sessionID, err)
		return nil, fmt.Errorf("refresh failed: %w", err)
	}
	providerRefreshSpan.End()
	expiresAt := time.Now().Unix() + int64(tr.ExpiresIn)
	if tr.ExpiresIn <= 0 {
		s.logger.Printf("warn: IdP omitted expires_in on refresh for session_id=%s, defaulting to 1 hour", sessionID)
		expiresAt = time.Now().Add(1 * time.Hour).Unix()
	}
	sess.AccessToken = tr.AccessToken
	sess.ExpiresAt = expiresAt
	if tr.RefreshToken != "" {
		s.logger.Printf("audit: refresh_token_rotated session_id=%s", sessionID)
		sess.RefreshToken = tr.RefreshToken
	}
	if tr.IDToken != "" {
		sess.IDToken = tr.IDToken
		aud := s.cfg.OIDCAudience
		if aud == "" {
			aud = s.cfg.OIDCClientID
		}
		_, validateSpan := s.tracer.StartSpan(ctx, "auth.token_validate_id_token_refresh")
		// nonce validation intentionally skipped on token refresh per OIDC Core §12.2
		principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, s.cfg.OIDCIssuer, aud, "")
		if err == nil && principal.Claims != nil {
			sess.Claims = principal.Claims
		}
		validateSpan.End()
	}
	_, sessionSetSpan := s.tracer.StartSpan(ctx, "auth.session_store_set")
	err = s.sessions.Set(ctx, sessionID, sess, s.cfg.SessionTTLSeconds)
	if err != nil {
		sessionSetSpan.End()
		return nil, err
	}
	sessionSetSpan.End()
	s.logger.Printf("audit: refresh_success session_id=%s", sessionID)
	_, cookieEncodeSpan := s.tracer.StartSpan(ctx, "auth.cookie_encode_session_id")
	cookieValue, err := s.cookie.Encode(sessionID)
	if err != nil {
		cookieEncodeSpan.End()
		return nil, err
	}
	cookieEncodeSpan.End()
	success = true
	return &auth.RefreshResponse{
		SetCookieValue: cookieValue,
		Refreshed:      true,
	}, nil
}

// EnsureFreshSessionByID loads a session and refreshes its OIDC tokens when the
// configured early-refresh window says they are close to expiry.
func (s *Service) EnsureFreshSessionByID(ctx context.Context, sessionID string) (*pkgsession.Session, bool, error) {
	if sessionID == "" {
		return nil, false, fmt.Errorf("session id required")
	}
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, false, fmt.Errorf("session not found")
	}
	if sess.RefreshToken == "" || !sess.NeedsRefresh(time.Now(), s.cfg.SessionRefreshEarlySeconds) {
		return sess, false, nil
	}
	ok, err := s.refreshLock.Obtain(ctx, sessionID, s.cfg.SessionRefreshLockTTLSeconds)
	if err != nil {
		return nil, false, fmt.Errorf("refresh lock obtain failed: %w", err)
	}
	if !ok {
		sess, err = s.sessions.Get(ctx, sessionID)
		if err != nil || sess == nil {
			return nil, false, fmt.Errorf("session not found")
		}
		return sess, false, nil
	}
	defer func() { _ = s.refreshLock.Release(ctx, sessionID) }()

	sess, err = s.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, false, fmt.Errorf("session not found")
	}
	if sess.RefreshToken == "" || !sess.NeedsRefresh(time.Now(), s.cfg.SessionRefreshEarlySeconds) {
		return sess, false, nil
	}

	tr, err := s.provider.Refresh(ctx, sess.RefreshToken)
	if err != nil {
		s.logger.Printf("audit: refresh_failed session_id=%s reason=%v", sessionID, err)
		return nil, false, fmt.Errorf("refresh failed: %w", err)
	}
	expiresAt := time.Now().Unix() + int64(tr.ExpiresIn)
	if tr.ExpiresIn <= 0 {
		s.logger.Printf("warn: IdP omitted expires_in on refresh for session_id=%s, defaulting to 1 hour", sessionID)
		expiresAt = time.Now().Add(1 * time.Hour).Unix()
	}
	sess.AccessToken = tr.AccessToken
	sess.ExpiresAt = expiresAt
	if tr.RefreshToken != "" {
		s.logger.Printf("audit: refresh_token_rotated session_id=%s", sessionID)
		sess.RefreshToken = tr.RefreshToken
	}
	if tr.IDToken != "" {
		sess.IDToken = tr.IDToken
		aud := s.cfg.OIDCAudience
		if aud == "" {
			aud = s.cfg.OIDCClientID
		}
		principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, s.cfg.OIDCIssuer, aud, "")
		if err == nil && principal.Claims != nil {
			sess.Claims = principal.Claims
		}
	}
	if err := s.sessions.Set(ctx, sessionID, sess, s.cfg.SessionTTLSeconds); err != nil {
		return nil, false, err
	}
	s.logger.Printf("audit: refresh_success session_id=%s", sessionID)
	return sess, true, nil
}

// Logout implements auth.Service.
func (s *Service) Logout(ctx context.Context, req auth.LogoutRequest) (*auth.LogoutResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.logout")
	defer span.End()
	defer s.metrics.LogoutCompleted()

	// CSRF: for POST, check Origin/Referer against allowed
	if req.Origin != "" || req.Referer != "" {
		allowed := false
		baseURL := strings.TrimSuffix(s.cfg.AppBaseURL, "/")
		for _, o := range s.cfg.AllowedRedirectOrigins {
			if req.Origin == o || req.Referer == o || req.Referer == baseURL+"/" || strings.HasPrefix(req.Referer, baseURL+"/") {
				allowed = true
				break
			}
		}
		if !allowed && (req.Origin != "" || req.Referer != "") {
			// Strict: require same origin
			if req.Origin != baseURL && req.Origin != "" {
				return nil, fmt.Errorf("csrf: origin not allowed")
			}
		}
	}
	redirectTo := ValidateRedirect(req.RedirectTo, s.cfg.AppBaseURL, s.cfg.AllowedRedirectOrigins, s.cfg.AllowedRedirectPaths)
	if redirectTo == "" {
		redirectTo = s.cfg.AppBaseURL
	}
	var sessionID string
	if req.SessionCookie != "" {
		_ = s.cookie.Decode(req.SessionCookie, &sessionID)
	}
	var idTokenHint string
	if sessionID != "" {
		_, sessGetSpan := s.tracer.StartSpan(ctx, "auth.session_store_get_logout")
		sess, _ := s.sessions.Get(ctx, sessionID)
		if sess != nil {
			idTokenHint = sess.IDToken
			_ = s.sessions.Delete(ctx, sessionID)
			s.logger.Printf("audit: logout session_id=%s subject=%s", sessionID, getClaimString(sess.Claims, "sub"))
		}
		sessGetSpan.End()
	}
	_, endURLSpan := s.tracer.StartSpan(ctx, "auth.oidc_end_session")
	endURL, err := s.provider.EndSessionURL(ctx, idTokenHint, redirectTo)
	if err != nil {
		endURLSpan.End()
		return &auth.LogoutResponse{RedirectURL: redirectTo, ClearCookie: true}, nil
	}
	endURLSpan.End()
	if endURL == "" {
		return &auth.LogoutResponse{RedirectURL: redirectTo, ClearCookie: true}, nil
	}
	return &auth.LogoutResponse{
		RedirectURL: endURL,
		ClearCookie: true,
	}, nil
}

func sessionToUser(sess *pkgsession.Session) *auth.SessionUser {
	return pkgsdk.SessionUserFromSession(sess)
}

func generateSessionID() (string, error) {
	b := make([]byte, 32) // 256 bits of cryptographic randomness
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Resolve returns access_token and claims for the proxy (internal use). If the session was refreshed, setCookieValue is non-empty.
func (s *Service) Resolve(ctx context.Context, sessionCookie string) (accessToken string, claims map[string]any, tenantContext map[string]any, setCookieValue string, err error) {
	if sessionCookie == "" {
		return "", nil, nil, "", fmt.Errorf("no session cookie")
	}
	var sessionID string
	if err := s.cookie.Decode(sessionCookie, &sessionID); err != nil {
		return "", nil, nil, "", fmt.Errorf("invalid cookie")
	}
	sess, refreshed, err := s.EnsureFreshSessionByID(ctx, sessionID)
	if err != nil {
		return "", nil, nil, "", err
	}
	claims = sess.Claims
	if claims == nil {
		claims = make(map[string]any)
	}
	var tc map[string]any
	if sess.TenantContext != nil {
		tc = map[string]any{
			"tenant_id":   sess.TenantContext.TenantID,
			"tenant_slug": sess.TenantContext.TenantSlug,
			"status":      sess.TenantContext.Status,
			"locale":      sess.TenantContext.Locale,
			"timezone":    sess.TenantContext.Timezone,
		}
	}
	cookieValue := ""
	if refreshed {
		cookieValue, err = s.cookie.Encode(sessionID)
		if err != nil {
			return "", nil, nil, "", err
		}
	}
	return sess.AccessToken, claims, tc, cookieValue, nil
}

// AttachTenantContext updates the session's tenant_context (Option A enrichment).
func (s *Service) AttachTenantContext(ctx context.Context, sessionID string, tc *pkgsession.TenantContext) error {
	if sessionID == "" || tc == nil {
		return fmt.Errorf("session_id and tenant_context required")
	}
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return fmt.Errorf("session not found")
	}
	sess.TenantContext = tc
	return s.sessions.Set(ctx, sessionID, sess, s.cfg.SessionTTLSeconds)
}

// Ensure Service implements auth.Service.
var _ auth.Service = (*Service)(nil)
