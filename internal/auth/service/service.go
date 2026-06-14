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
	"strconv"
	"strings"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/internal/auth/handoff"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/pkg/auth"
	"github.com/accessgate/accessgate/pkg/cookie"
	"github.com/accessgate/accessgate/pkg/observability"
	"github.com/accessgate/accessgate/pkg/oidc"
	pkgsdk "github.com/accessgate/accessgate/pkg/sdk"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
	"github.com/accessgate/accessgate/pkg/token"
)

// SubjectEmailFinder locates a session by subject+email within a connector's namespace.
// The Redis store implements it; it is optional per connector (needed only for handoff issue).
type SubjectEmailFinder interface {
	FindSessionBySubjectEmail(ctx context.Context, subject, email string) (*pkgsession.Session, error)
}

// connector bundles the per-connector runtime state: its provider, namespaced stores,
// cookie, and resolved config. One auth Service holds one or more connectors.
type connector struct {
	cfg         config.ConnectorConfig
	provider    plugin.ProviderPlugin
	sessions    pkgsession.SessionStore
	pkce        pkgsession.PKCEStore
	refreshLock pkgsession.RefreshLockStore
	finder      SubjectEmailFinder
	cookieName  string
	cookieOpts  cookie.CookieOptions
}

// Connector is the wiring for one identity connector passed to NewMultiConnector.
type Connector struct {
	Config      config.ConnectorConfig
	Provider    plugin.ProviderPlugin
	Sessions    pkgsession.SessionStore
	PKCE        pkgsession.PKCEStore
	RefreshLock pkgsession.RefreshLockStore
	// Finder is optional; when set it enables handoff ticket issuance for this connector.
	Finder SubjectEmailFinder
}

// Service implements auth.Service.
type Service struct {
	cfg           *config.Config
	connectors    map[string]*connector
	defaultID     string
	jwks          token.JWKSSource
	cookie        cookie.Manager
	handoff       *handoff.Issuer
	tracer        observability.Tracer
	metrics       observability.Metrics
	logger        *log.Logger
	webhookClient *http.Client
}

// New creates a single-connector accessgate-auth Service from explicit stores and provider.
// It is the backward-compatible constructor: the connector is synthesized from cfg's default
// connector (when present) or the legacy top-level OIDC fields.
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
	conns := []Connector{{
		Config:      defaultConnectorConfig(cfg),
		Provider:    provider,
		Sessions:    sessions,
		PKCE:        pkce,
		RefreshLock: refreshLock,
	}}
	return newService(cfg, conns, cookieManager, jwks, tracer, metrics)
}

// NewWithRuntimeStoreProvider creates a single-connector Service from the runtime store seam.
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

// NewMultiConnector creates a Service hosting multiple identity connectors. Each Connector
// carries its own provider and namespaced stores (built by the caller from cfg.Connectors).
func NewMultiConnector(
	cfg *config.Config,
	connectors []Connector,
	cookieManager cookie.Manager,
	jwks token.JWKSSource,
	tracer observability.Tracer,
	metrics observability.Metrics,
) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(connectors) == 0 {
		return nil, fmt.Errorf("at least one connector is required")
	}
	return newService(cfg, connectors, cookieManager, jwks, tracer, metrics)
}

func newService(
	cfg *config.Config,
	connectors []Connector,
	cookieManager cookie.Manager,
	jwks token.JWKSSource,
	tracer observability.Tracer,
	metrics observability.Metrics,
) (*Service, error) {
	if tracer == nil {
		tracer = observability.NopTracer{}
	}
	if metrics == nil {
		metrics = observability.NopMetrics{}
	}
	s := &Service{
		cfg:           cfg,
		connectors:    make(map[string]*connector, len(connectors)),
		jwks:          jwks,
		cookie:        cookieManager,
		tracer:        tracer,
		metrics:       metrics,
		logger:        log.New(log.Writer(), "[accessgate-auth] ", log.LstdFlags|log.LUTC),
		webhookClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, c := range connectors {
		if c.Provider == nil {
			return nil, fmt.Errorf("connector %q: provider is required", c.Config.ID)
		}
		id := c.Config.ID
		if id == "" {
			id = "default"
		}
		cookieName := c.Config.CookieName
		if cookieName == "" {
			cookieName = cfg.CookieName
		}
		maxAge := c.Config.SessionTTLSeconds
		if maxAge == 0 {
			maxAge = cfg.SessionTTLSeconds
		}
		s.connectors[id] = &connector{
			cfg:         c.Config,
			provider:    c.Provider,
			sessions:    c.Sessions,
			pkce:        c.PKCE,
			refreshLock: c.RefreshLock,
			finder:      c.Finder,
			cookieName:  cookieName,
			cookieOpts: cookie.CookieOptions{
				Path:     "/",
				Domain:   cfg.CookieDomain,
				Secure:   bool(cfg.CookieSecure),
				HTTPOnly: true,
				SameSite: cfg.CookieSameSite,
				MaxAge:   maxAge,
			},
		}
		// The connector marked default wins; otherwise the first connector is the default.
		if bool(c.Config.Default) || s.defaultID == "" {
			s.defaultID = id
		}
	}
	return s, nil
}

// defaultConnectorConfig returns cfg's default connector when present, else a connector
// config derived from the legacy top-level OIDC fields (with sub/oidc_sub claim mapping).
func defaultConnectorConfig(cfg *config.Config) config.ConnectorConfig {
	if dc := cfg.DefaultConnector(); dc != nil {
		return *dc
	}
	return config.ConnectorConfig{
		ID:                           "default",
		Default:                      true,
		ProviderPluginID:             cfg.ProviderPluginID,
		OIDCIssuer:                   cfg.OIDCIssuer,
		OIDCRedirectURI:              cfg.OIDCRedirectURI,
		OIDCClientID:                 cfg.OIDCClientID,
		OIDCClientSecret:             cfg.OIDCClientSecret,
		OIDCScopes:                   cfg.OIDCScopes,
		OIDCAudience:                 cfg.OIDCAudience,
		OIDCClaimsSource:             cfg.OIDCClaimsSource,
		SessionRedisPrefix:           cfg.SessionRedisPrefix,
		CookieName:                   cfg.CookieName,
		SessionTTLSeconds:            cfg.SessionTTLSeconds,
		SessionPKCETTLSeconds:        cfg.SessionPKCETTLSeconds,
		SessionRefreshLockTTLSeconds: cfg.SessionRefreshLockTTLSeconds,
		ClaimMapping:                 config.ClaimMappingConfig{AuthoritativeIDClaim: "sub", IDKind: "oidc_sub"},
	}
}

// conn resolves a connector by id; an empty id selects the default connector.
func (s *Service) conn(id string) (*connector, error) {
	if id == "" {
		id = s.defaultID
	}
	c, ok := s.connectors[id]
	if !ok {
		return nil, fmt.Errorf("unknown connector %q", id)
	}
	return c, nil
}

// ConnectorCookieName returns the session cookie name for the given connector
// (empty id = default). It lets the HTTP layer read/write the right cookie.
func (s *Service) ConnectorCookieName(id string) string {
	c, err := s.conn(id)
	if err != nil {
		return s.cfg.CookieName
	}
	return c.cookieName
}

// Session implements auth.Service.
func (s *Service) Session(ctx context.Context, req auth.SessionRequest) (*auth.SessionResponse, error) {
	if req.SessionCookie == "" {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	c, err := s.conn(req.Connector)
	if err != nil {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	var sessionID string
	if err := s.cookie.Decode(req.SessionCookie, &sessionID); err != nil {
		return &auth.SessionResponse{IsAuthenticated: false}, nil
	}
	sess, err := c.sessions.Get(ctx, sessionID)
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
	ctx, span := s.tracer.StartSpan(ctx, "auth.login_start", "connector", req.Connector, "redirect_to", req.RedirectTo)
	defer span.End()
	s.metrics.LoginStarted()

	c, err := s.conn(req.Connector)
	if err != nil {
		return nil, err
	}

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
	err = c.pkce.Set(ctx, state, &pkgsession.PKCEState{
		State:         state,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Nonce:         nonce,
		RedirectTo:    redirectTo,
	}, c.cfg.SessionPKCETTLSeconds)
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
	authURL, err := c.provider.AuthorizationURL(ctx, state, challenge, nonce, extraParams)
	if err != nil {
		authURLSpan.End()
		return nil, err
	}
	authURLSpan.End()
	return &auth.LoginStartResponse{RedirectURL: authURL}, nil
}

// LoginEnd implements auth.Service.
func (s *Service) LoginEnd(ctx context.Context, req auth.LoginEndRequest) (*auth.LoginEndResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.login_end", "connector", req.Connector, "state_present", req.State != "", "code_present", req.Code != "")
	defer span.End()
	success := false
	defer func() { s.metrics.LoginCompleted(success) }()

	c, err := s.conn(req.Connector)
	if err != nil {
		return nil, err
	}
	defer func() { s.metrics.ConnectorCallback(c.cfg.ID, success) }()

	if req.Error != "" {
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	if req.State == "" || req.Code == "" {
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	_, pkceGetSpan := s.tracer.StartSpan(ctx, "auth.pkce_get")
	p, err := c.pkce.Get(ctx, req.State)
	if err != nil || p == nil {
		pkceGetSpan.End()
		s.logger.Printf("audit: login_end pkce_miss connector=%s host=%s", c.cfg.ID, req.Host)
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	pkceGetSpan.End()
	_ = c.pkce.Delete(ctx, req.State)
	_, exchangeSpan := s.tracer.StartSpan(ctx, "auth.oidc_exchange_code")
	tr, err := c.provider.ExchangeCode(ctx, req.Code, p.CodeVerifier, c.cfg.OIDCRedirectURI)
	if err != nil {
		exchangeSpan.End()
		s.logger.Printf("audit: login_end exchange_failed connector=%s host=%s", c.cfg.ID, req.Host)
		redirectURL := s.cfg.AppBaseURL + s.cfg.LoginErrorRedirectPath
		return &auth.LoginEndResponse{RedirectURL: redirectURL, ClearCookie: true}, nil
	}
	exchangeSpan.End()
	audience := c.cfg.OIDCAudience
	if audience == "" {
		audience = c.cfg.OIDCClientID
	}
	_, validateSpan := s.tracer.StartSpan(ctx, "auth.token_validate_id_token")
	principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, c.cfg.OIDCIssuer, audience, p.Nonce)
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
	// Connector-specific identity normalization: choose the authoritative downstream id
	// (e.g. a Telegram numeric id) per the connector's claim-mapping policy, falling back
	// to the OIDC sub. Carried in claims["sub"] so it flows unchanged to the proxy and
	// downstream X-User-Id, with the source recorded for observability/audit.
	authID := principal.Subject
	if mapped := s.authoritativeID(c, principal.Claims); mapped != "" {
		authID = mapped
	}
	claims["sub"] = authID
	if c.cfg.ClaimMapping.IDKind != "" {
		claims["authoritative_id_kind"] = c.cfg.ClaimMapping.IDKind
	}
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
	err = c.sessions.Set(ctx, sessID, sess, c.cfg.SessionTTLSeconds)
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

// authoritativeID returns the connector's authoritative downstream id from the IdP claims,
// per its ClaimMapping. Returns "" when the configured claim is "sub" (use principal.Subject)
// or is absent. Numeric ids (e.g. Telegram) are coerced to their string form.
func (s *Service) authoritativeID(c *connector, claims map[string]any) string {
	key := c.cfg.ClaimMapping.AuthoritativeIDClaim
	if key == "" || key == "sub" || claims == nil {
		return ""
	}
	return claimToString(claims[key])
}

// claimToString coerces a claim value (string or JSON number) to a string. It returns ""
// for absent or non-scalar values so callers fall back to the default id.
func claimToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		// JSON numbers decode to float64; render integers without a decimal point.
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	default:
		return ""
	}
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
	ctx, span := s.tracer.StartSpan(ctx, "auth.refresh", "connector", req.Connector)
	defer span.End()
	success := false
	defer func() { s.metrics.RefreshCompleted(success) }()

	c, err := s.conn(req.Connector)
	if err != nil {
		return nil, err
	}
	if req.SessionCookie == "" {
		return nil, fmt.Errorf("no session cookie")
	}
	var sessionID string
	if err := s.cookie.Decode(req.SessionCookie, &sessionID); err != nil {
		return nil, fmt.Errorf("invalid cookie")
	}
	_, sessionGetSpan := s.tracer.StartSpan(ctx, "auth.session_store_get")
	sess, err := c.sessions.Get(ctx, sessionID)
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
	ok, err := c.refreshLock.Obtain(ctx, sessionID, c.cfg.SessionRefreshLockTTLSeconds)
	if err != nil || !ok {
		lockSpan.End()
		return &auth.RefreshResponse{}, nil
	}
	lockSpan.End()
	defer func() { _ = c.refreshLock.Release(ctx, sessionID) }()
	_, providerRefreshSpan := s.tracer.StartSpan(ctx, "auth.oidc_refresh")
	tr, err := c.provider.Refresh(ctx, sess.RefreshToken)
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
		aud := c.cfg.OIDCAudience
		if aud == "" {
			aud = c.cfg.OIDCClientID
		}
		_, validateSpan := s.tracer.StartSpan(ctx, "auth.token_validate_id_token_refresh")
		// nonce validation intentionally skipped on token refresh per OIDC Core §12.2
		principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, c.cfg.OIDCIssuer, aud, "")
		if err == nil && principal.Claims != nil {
			s.applyRefreshedClaims(c, sess, principal.Claims)
		}
		validateSpan.End()
	}
	_, sessionSetSpan := s.tracer.StartSpan(ctx, "auth.session_store_set")
	err = c.sessions.Set(ctx, sessionID, sess, c.cfg.SessionTTLSeconds)
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

// applyRefreshedClaims replaces the session claims with the refreshed token's claims while
// preserving the connector's authoritative downstream id. If the refreshed token omits the
// configured authoritative claim (e.g. a Telegram refresh that carries no tg id), the prior
// established id and kind are retained so the downstream identity stays stable.
func (s *Service) applyRefreshedClaims(c *connector, sess *pkgsession.Session, newClaims map[string]any) {
	prevSub := getClaimString(sess.Claims, "sub")
	prevKind := getClaimString(sess.Claims, "authoritative_id_kind")
	sess.Claims = newClaims
	authID := getClaimString(newClaims, "sub")
	if mapped := s.authoritativeID(c, newClaims); mapped != "" {
		authID = mapped
	} else if c.cfg.ClaimMapping.AuthoritativeIDClaim != "" && c.cfg.ClaimMapping.AuthoritativeIDClaim != "sub" && prevSub != "" {
		authID = prevSub
	}
	if authID != "" {
		newClaims["sub"] = authID
	}
	switch {
	case c.cfg.ClaimMapping.IDKind != "":
		newClaims["authoritative_id_kind"] = c.cfg.ClaimMapping.IDKind
	case prevKind != "":
		newClaims["authoritative_id_kind"] = prevKind
	}
}

// EnsureFreshSessionByID loads a session from the default connector and refreshes its OIDC
// tokens when close to expiry. Retained for backward compatibility; multi-connector callers
// should use EnsureFreshSessionForConnector.
func (s *Service) EnsureFreshSessionByID(ctx context.Context, sessionID string) (*pkgsession.Session, bool, error) {
	c, err := s.conn("")
	if err != nil {
		return nil, false, err
	}
	return s.ensureFresh(ctx, c, sessionID)
}

// EnsureFreshSessionForConnector loads a session from the named connector (empty = default)
// and refreshes its OIDC tokens when close to expiry.
func (s *Service) EnsureFreshSessionForConnector(ctx context.Context, connectorID, sessionID string) (*pkgsession.Session, bool, error) {
	c, err := s.conn(connectorID)
	if err != nil {
		return nil, false, err
	}
	return s.ensureFresh(ctx, c, sessionID)
}

func (s *Service) ensureFresh(ctx context.Context, c *connector, sessionID string) (*pkgsession.Session, bool, error) {
	if sessionID == "" {
		return nil, false, fmt.Errorf("session id required")
	}
	sess, err := c.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, false, fmt.Errorf("session not found")
	}
	if sess.RefreshToken == "" || !sess.NeedsRefresh(time.Now(), s.cfg.SessionRefreshEarlySeconds) {
		return sess, false, nil
	}
	ok, err := c.refreshLock.Obtain(ctx, sessionID, c.cfg.SessionRefreshLockTTLSeconds)
	if err != nil {
		return nil, false, fmt.Errorf("refresh lock obtain failed: %w", err)
	}
	if !ok {
		sess, err = c.sessions.Get(ctx, sessionID)
		if err != nil || sess == nil {
			return nil, false, fmt.Errorf("session not found")
		}
		return sess, false, nil
	}
	defer func() { _ = c.refreshLock.Release(ctx, sessionID) }()

	sess, err = c.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return nil, false, fmt.Errorf("session not found")
	}
	if sess.RefreshToken == "" || !sess.NeedsRefresh(time.Now(), s.cfg.SessionRefreshEarlySeconds) {
		return sess, false, nil
	}

	tr, err := c.provider.Refresh(ctx, sess.RefreshToken)
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
		aud := c.cfg.OIDCAudience
		if aud == "" {
			aud = c.cfg.OIDCClientID
		}
		principal, err := token.ValidateIDToken(ctx, tr.IDToken, s.jwks, c.cfg.OIDCIssuer, aud, "")
		if err == nil && principal.Claims != nil {
			s.applyRefreshedClaims(c, sess, principal.Claims)
		}
	}
	if err := c.sessions.Set(ctx, sessionID, sess, c.cfg.SessionTTLSeconds); err != nil {
		return nil, false, err
	}
	s.logger.Printf("audit: refresh_success session_id=%s", sessionID)
	return sess, true, nil
}

// Logout implements auth.Service.
func (s *Service) Logout(ctx context.Context, req auth.LogoutRequest) (*auth.LogoutResponse, error) {
	ctx, span := s.tracer.StartSpan(ctx, "auth.logout", "connector", req.Connector)
	defer span.End()
	defer s.metrics.LogoutCompleted()

	c, err := s.conn(req.Connector)
	if err != nil {
		return nil, err
	}

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
		sess, _ := c.sessions.Get(ctx, sessionID)
		if sess != nil {
			idTokenHint = sess.IDToken
			_ = c.sessions.Delete(ctx, sessionID)
			s.logger.Printf("audit: logout session_id=%s subject=%s", sessionID, getClaimString(sess.Claims, "sub"))
		}
		sessGetSpan.End()
	}
	_, endURLSpan := s.tracer.StartSpan(ctx, "auth.oidc_end_session")
	endURL, err := c.provider.EndSessionURL(ctx, idTokenHint, redirectTo)
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

// Resolve returns access_token and claims for the proxy (internal use), using the default
// connector. If the session was refreshed, setCookieValue is non-empty.
func (s *Service) Resolve(ctx context.Context, sessionCookie string) (accessToken string, claims map[string]any, tenantContext map[string]any, setCookieValue string, err error) {
	return s.ResolveForConnector(ctx, "", sessionCookie)
}

// ResolveForConnector resolves a session against the named connector (empty = default).
func (s *Service) ResolveForConnector(ctx context.Context, connectorID, sessionCookie string) (accessToken string, claims map[string]any, tenantContext map[string]any, setCookieValue string, err error) {
	if sessionCookie == "" {
		return "", nil, nil, "", fmt.Errorf("no session cookie")
	}
	c, err := s.conn(connectorID)
	if err != nil {
		return "", nil, nil, "", err
	}
	var sessionID string
	if err := s.cookie.Decode(sessionCookie, &sessionID); err != nil {
		return "", nil, nil, "", fmt.Errorf("invalid cookie")
	}
	sess, refreshed, err := s.ensureFresh(ctx, c, sessionID)
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

// AttachTenantContext updates the session's tenant_context on the default connector
// (Option A enrichment). Multi-connector callers should use AttachTenantContextForConnector.
func (s *Service) AttachTenantContext(ctx context.Context, sessionID string, tc *pkgsession.TenantContext) error {
	return s.AttachTenantContextForConnector(ctx, "", sessionID, tc)
}

// AttachTenantContextForConnector updates the session's tenant_context on the named connector
// (empty = default).
func (s *Service) AttachTenantContextForConnector(ctx context.Context, connectorID, sessionID string, tc *pkgsession.TenantContext) error {
	if sessionID == "" || tc == nil {
		return fmt.Errorf("session_id and tenant_context required")
	}
	c, err := s.conn(connectorID)
	if err != nil {
		return err
	}
	sess, err := c.sessions.Get(ctx, sessionID)
	if err != nil || sess == nil {
		return fmt.Errorf("session not found")
	}
	sess.TenantContext = tc
	return c.sessions.Set(ctx, sessionID, sess, c.cfg.SessionTTLSeconds)
}

// EnableHandoff turns on the signed one-time handoff ticket feature, signing tickets with the
// cookie signing secret and using once for replay protection. ttlSeconds<=0 uses the default.
func (s *Service) EnableHandoff(once handoff.OnceStore, ttlSeconds int) {
	s.handoff = handoff.NewIssuer(s.cfg.CookieSigningSecret, time.Duration(ttlSeconds)*time.Second, once)
}

// HandoffEnabled reports whether handoff issuance/redemption is configured.
func (s *Service) HandoffEnabled() bool { return s.handoff != nil }

// IssueHandoff mints a one-time handoff ticket for the user's existing session on the named
// connector (empty = default), located by subject+email. The connector must have a Finder.
func (s *Service) IssueHandoff(ctx context.Context, connectorID, subject, email string) (string, error) {
	if s.handoff == nil {
		return "", fmt.Errorf("handoff not enabled")
	}
	c, err := s.conn(connectorID)
	if err != nil {
		return "", err
	}
	if c.finder == nil {
		return "", fmt.Errorf("handoff: connector %q has no session finder", c.cfg.ID)
	}
	sess, err := c.finder.FindSessionBySubjectEmail(ctx, subject, email)
	if err != nil {
		return "", fmt.Errorf("handoff: session lookup failed: %w", err)
	}
	if sess == nil {
		return "", fmt.Errorf("handoff: session not found")
	}
	jti, err := generateSessionID()
	if err != nil {
		return "", err
	}
	ctx, span := s.tracer.StartSpan(ctx, "auth.handoff_issue", "connector", c.cfg.ID)
	defer span.End()
	authID := getClaimString(sess.Claims, "sub")
	ticket, err := s.handoff.Issue(c.cfg.ID, authID, sess.ID, jti)
	s.metrics.HandoffIssued(c.cfg.ID, err == nil)
	return ticket, err
}

// RedeemHandoff verifies and one-time-consumes a handoff ticket, confirms the referenced
// session still exists on its connector, and returns the encoded session cookie value plus
// the connector id the cookie belongs to. connectorID (from the redeem path) must match the
// ticket's connector when non-empty.
func (s *Service) RedeemHandoff(ctx context.Context, connectorID, ticket string) (cookieValue, connector string, err error) {
	if s.handoff == nil {
		return "", "", fmt.Errorf("handoff not enabled")
	}
	ctx, span := s.tracer.StartSpan(ctx, "auth.handoff_redeem", "connector", connectorID)
	defer span.End()
	defer func() {
		label := connector
		if label == "" {
			label = connectorID
		}
		s.metrics.HandoffRedeemed(label, err == nil)
	}()
	t, err := s.handoff.Redeem(ctx, ticket)
	if err != nil {
		return "", "", err
	}
	if connectorID != "" && t.ConnectorID != connectorID {
		return "", "", fmt.Errorf("handoff: connector mismatch")
	}
	c, err := s.conn(t.ConnectorID)
	if err != nil {
		return "", "", err
	}
	sess, err := c.sessions.Get(ctx, t.SessionRef)
	if err != nil || sess == nil {
		return "", "", fmt.Errorf("handoff: session not found")
	}
	v, err := s.cookie.Encode(t.SessionRef)
	if err != nil {
		return "", "", err
	}
	return v, t.ConnectorID, nil
}

// ValidateRedirectURL validates a post-redemption redirect target against the configured
// allow-lists, returning the app base URL when the target is empty or disallowed.
func (s *Service) ValidateRedirectURL(redirectTo string) string {
	v := ValidateRedirect(redirectTo, s.cfg.AppBaseURL, s.cfg.AllowedRedirectOrigins, s.cfg.AllowedRedirectPaths)
	if v == "" {
		return s.cfg.AppBaseURL
	}
	return v
}

// Ensure Service implements auth.Service.
var _ auth.Service = (*Service)(nil)
