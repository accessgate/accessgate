package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/internal/auth/errormap"
	"github.com/accessgate/accessgate/internal/auth/service"
	"github.com/accessgate/accessgate/pkg/auth"
	pkgsession "github.com/accessgate/accessgate/pkg/session"
)

// Pinger is used for readiness checks (e.g. Redis).
type Pinger interface {
	Ping(ctx context.Context) error
}

type delegatedSessionLookup interface {
	FindSessionBySubjectEmail(ctx context.Context, subject, email string) (*pkgsession.Session, error)
}

type adminSessionLookupStore interface {
	DeleteSessionsBySubjectEmail(ctx context.Context, subject, email string) (int, error)
}

// Server is the HTTP server for accessgate-auth.
type Server struct {
	mux    *http.ServeMux
	svc    auth.Service
	cfg    *config.Config
	cookie string
	ping   Pinger // optional; used for /readyz
	// metricsHandler is optional; when set, GET /metrics is registered.
	metricsHandler http.Handler
	logger         *log.Logger
}

// New constructs a new Server with the given service and config. If pinger is non-nil, /readyz will use it.
func New(svc auth.Service, cfg *config.Config, pinger Pinger, metricsHandler http.Handler) *Server {
	s := &Server{
		mux:            http.NewServeMux(),
		svc:            svc,
		cfg:            cfg,
		cookie:         cfg.CookieName,
		ping:           pinger,
		metricsHandler: metricsHandler,
		logger:         log.New(log.Writer(), "[accessgate-auth] ", log.LstdFlags|log.LUTC),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /livez", s.handleLivez)
	if s.cfg.AdminSecret != "" {
		s.mux.HandleFunc("GET /admin", s.handleAdmin)
		s.mux.HandleFunc("PATCH /internal/session", s.handlePatchSession)
		s.mux.HandleFunc("POST /internal/session", s.handlePatchSession)
		s.mux.HandleFunc("POST /internal/session/revoke", s.handleRevokeSession)
		s.mux.HandleFunc("POST /internal/token-handoff/user", s.handleTokenHandoffUser)
	}
	if s.metricsHandler != nil {
		s.mux.Handle("GET /metrics", s.metricsHandler)
	}
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("GET /callback", s.handleCallback)
	s.mux.HandleFunc("POST /callback", s.handleCallback)
	s.mux.HandleFunc("GET /session", s.handleSession)
	s.mux.HandleFunc("GET /me", s.handleMe)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /refresh", s.handleRefresh)
	s.mux.HandleFunc("GET /internal/resolve", s.handleResolve)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.ping != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.ping.Ping(ctx); err != nil {
			s.logger.Printf("readyz: ping failed: %v", err)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("unhealthy"))
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Secret")), []byte(s.cfg.AdminSecret)) != 1 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	out := map[string]any{
		"config_summary": s.authConfigSummary(),
		"session_store":  s.sessionStoreStatus(r.Context()),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) authConfigSummary() map[string]any {
	return map[string]any{
		"oidc_issuer":       s.cfg.OIDCIssuer,
		"oidc_redirect_uri": s.cfg.OIDCRedirectURI,
		"cookie_name":       s.cfg.CookieName,
		"http_port":         s.cfg.HTTPPort,
		"redis_url_set":     s.cfg.RedisURL != "",
		"app_base_url":      s.cfg.AppBaseURL,
	}
}

func (s *Server) sessionStoreStatus(ctx context.Context) map[string]any {
	if s.ping == nil {
		return map[string]any{"status": "unknown", "message": "no pinger"}
	}
	if err := s.ping.Ping(ctx); err != nil {
		return map[string]any{"status": "error", "error": err.Error()}
	}
	return map[string]any{"status": "ok"}
}

// Handler returns the HTTP handler (with optional CORS and security headers).
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	if len(s.cfg.CORSAllowedOriginsSlice()) > 0 {
		h = cors(s.cfg.CORSAllowedOriginsSlice())(h)
	}
	return securityHeaders(h)
}

// securityHeaders adds defensive HTTP response headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			for _, o := range origins {
				if o == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) getCookie(r *http.Request) string {
	c, _ := r.Cookie(s.cookie)
	if c != nil {
		return c.Value
	}
	return ""
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	prompt := strings.TrimSpace(r.URL.Query().Get("prompt"))
	resp, err := s.svc.LoginStart(r.Context(), auth.LoginStartRequest{RedirectTo: redirectTo, Prompt: prompt})
	if err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	req := auth.LoginEndRequest{
		Code:             r.URL.Query().Get("code"),
		State:            r.URL.Query().Get("state"),
		Error:            r.URL.Query().Get("error"),
		ErrorDescription: r.URL.Query().Get("error_description"),
		Host:             r.Host,
	}
	if req.Error == "" && req.Code == "" {
		req.Error = r.FormValue("error")
		req.ErrorDescription = r.FormValue("error_description")
		req.Code = r.FormValue("code")
		req.State = r.FormValue("state")
	}
	resp, err := s.svc.LoginEnd(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	if resp.ClearCookie {
		// Clear cookie by setting MaxAge=-1 (handled by cookie manager in response)
		w.Header().Set("Set-Cookie", s.cookie+"=; Path=/; Max-Age=0; HttpOnly")
		if bool(s.cfg.CookieSecure) {
			w.Header().Add("Set-Cookie", s.cookie+"=; Path=/; Max-Age=0; HttpOnly; Secure")
		}
	}
	if resp.SetCookieValue != "" {
		path, domain, maxAge, secure, httpOnly, sameSite := s.cookieOpts()
		writeSessionCookie(w, s.cookie, resp.SetCookieValue, path, domain, maxAge, secure, httpOnly, sameSite)
	}
	http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
}

func (s *Server) cookieOpts() (path, domain string, maxAge int, secure, httpOnly bool, sameSite string) {
	path = "/"
	domain = s.cfg.CookieDomain
	maxAge = s.cfg.SessionTTLSeconds
	secure = bool(s.cfg.CookieSecure)
	if strings.HasPrefix(s.cookie, "__Host-") {
		secure = true
		domain = ""
	}
	httpOnly = true
	sameSite = "Lax"
	switch s.cfg.CookieSameSite {
	case http.SameSiteStrictMode:
		sameSite = "Strict"
	case http.SameSiteNoneMode:
		sameSite = "None"
	}
	return path, domain, maxAge, secure, httpOnly, sameSite
}

func writeSessionCookie(w http.ResponseWriter, name, value, path, domain string, maxAge int, secure, httpOnly bool, sameSite string) {
	v := name + "=" + value + "; Path=" + path + "; Max-Age=" + strconv.Itoa(maxAge) + "; HttpOnly"
	if domain != "" {
		v += "; Domain=" + domain
	}
	if secure {
		v += "; Secure"
	}
	v += "; SameSite=" + sameSite
	w.Header().Add("Set-Cookie", v)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	resp, err := s.svc.Session(r.Context(), auth.SessionRequest{SessionCookie: s.getCookie(r)})
	if err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	if resp.SetCookie != "" {
		path, domain, maxAge, secure, httpOnly, sameSite := s.cookieOpts()
		writeSessionCookie(w, s.cookie, resp.SetCookie, path, domain, maxAge, secure, httpOnly, sameSite)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"is_authenticated": resp.IsAuthenticated,
		"user":             resp.User,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	resp, err := s.svc.Session(r.Context(), auth.SessionRequest{SessionCookie: s.getCookie(r)})
	if err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	if !resp.IsAuthenticated || resp.User == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp.User)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		redirectTo = r.FormValue("redirect_to")
	}
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	resp, err := s.svc.Logout(r.Context(), auth.LogoutRequest{
		SessionCookie: s.getCookie(r),
		RedirectTo:    redirectTo,
		Origin:        origin,
		Referer:       referer,
	})
	if err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	if resp.ClearCookie {
		w.Header().Set("Set-Cookie", s.cookie+"=; Path=/; Max-Age=0; HttpOnly")
		if bool(s.cfg.CookieSecure) {
			w.Header().Add("Set-Cookie", s.cookie+"=; Path=/; Max-Age=0; HttpOnly; Secure")
		}
	}
	http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	resp, err := s.svc.Refresh(r.Context(), auth.RefreshRequest{SessionCookie: s.getCookie(r)})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	if resp.Refreshed && resp.SetCookieValue != "" {
		path, domain, maxAge, secure, httpOnly, sameSite := s.cookieOpts()
		writeSessionCookie(w, s.cookie, resp.SetCookieValue, path, domain, maxAge, secure, httpOnly, sameSite)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	svc, ok := s.svc.(*service.Service)
	if !ok {
		http.Error(w, "not available", http.StatusNotImplemented)
		return
	}
	accessToken, claims, tenantContext, setCookie, err := svc.Resolve(r.Context(), s.getCookie(r))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	if setCookie != "" {
		path, domain, maxAge, secure, httpOnly, sameSite := s.cookieOpts()
		writeSessionCookie(w, s.cookie, setCookie, path, domain, maxAge, secure, httpOnly, sameSite)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":   accessToken,
		"claims":         claims,
		"tenant_context": tenantContext,
	})
}

func (s *Server) handlePatchSession(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Secret")), []byte(s.cfg.AdminSecret)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		return
	}
	enricher, ok := s.svc.(*service.Service)
	if !ok {
		http.Error(w, "not available", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		SessionID     string                    `json:"session_id"`
		TenantContext *pkgsession.TenantContext `json:"tenant_context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if body.SessionID == "" || body.TenantContext == nil {
		http.Error(w, "session_id and tenant_context required", http.StatusBadRequest)
		return
	}
	if err := enricher.AttachTenantContext(r.Context(), body.SessionID, body.TenantContext); err != nil {
		http.Error(w, err.Error(), errormap.StatusFor(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Secret")), []byte(s.cfg.AdminSecret)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		return
	}
	store, ok := s.ping.(adminSessionLookupStore)
	if !ok {
		http.Error(w, "not available", http.StatusNotImplemented)
		return
	}
	var body struct {
		Lookup struct {
			Subject string `json:"subject"`
			Email   string `json:"email"`
		} `json:"lookup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if body.Lookup.Subject == "" || body.Lookup.Email == "" {
		http.Error(w, "lookup.subject and lookup.email required", http.StatusBadRequest)
		return
	}
	deleted, err := store.DeleteSessionsBySubjectEmail(r.Context(), body.Lookup.Subject, body.Lookup.Email)
	if err != nil {
		http.Error(w, "session delete failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"revoked": deleted > 0, "deleted_count": deleted})
}

func (s *Server) handleTokenHandoffUser(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Secret")), []byte(s.cfg.AdminSecret)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		return
	}
	lookup, ok := s.ping.(delegatedSessionLookup)
	if !ok {
		http.Error(w, "not available", http.StatusNotImplemented)
		return
	}
	var body struct {
		Lookup struct {
			Subject       string `json:"subject"`
			Email         string `json:"email"`
			IdentityID    string `json:"identity_id,omitempty"`
			Channel       string `json:"channel,omitempty"`
			ChannelUserID string `json:"channel_user_id,omitempty"`
		} `json:"lookup"`
		TokenUse string `json:"token_use"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if body.Lookup.Subject == "" || body.Lookup.Email == "" {
		http.Error(w, "lookup.subject and lookup.email required", http.StatusBadRequest)
		return
	}
	if body.TokenUse != "" && body.TokenUse != "peoplespace_user_api" {
		http.Error(w, "unsupported token_use", http.StatusBadRequest)
		return
	}
	sess, err := lookup.FindSessionBySubjectEmail(r.Context(), body.Lookup.Subject, body.Lookup.Email)
	if err != nil {
		http.Error(w, "session lookup failed", http.StatusInternalServerError)
		return
	}
	if sess == nil || sess.AccessToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no_active_delegated_token"}`))
		return
	}
	if svc, ok := s.svc.(*service.Service); ok && sess.ID != "" {
		refreshed, _, err := svc.EnsureFreshSessionByID(r.Context(), sess.ID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("{\"error\":\"unauthorized\"}"))
			return
		}
		sess = refreshed
	}
	resp := map[string]any{
		"access_token":      sess.AccessToken,
		"id_token":          sess.IDToken,
		"scope":             "",
		"refresh_owner":     "accessgate",
		"access_expires_at": time.Unix(sess.ExpiresAt, 0).UTC().Format(time.RFC3339),
	}
	if sess.RefreshToken != "" {
		resp["refresh_token"] = sess.RefreshToken
		resp["refresh_owner"] = "platform-api"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
