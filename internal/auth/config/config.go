package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArmanAvanesyan/accessgate/pkg/session"
)

// FlexibleBool allows configuration values to be provided either as JSON booleans
// (e.g. `true`) or as JSON strings (e.g. `"true"`), which is helpful for env->config loaders.
type FlexibleBool bool

func (b *FlexibleBool) UnmarshalJSON(data []byte) error {
	var v bool
	if err := json.Unmarshal(data, &v); err == nil {
		*b = FlexibleBool(v)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true", "1", "yes", "y":
			*b = FlexibleBool(true)
			return nil
		case "false", "0", "no", "n":
			*b = FlexibleBool(false)
			return nil
		default:
			return fmt.Errorf("invalid flexible bool %q", s)
		}
	}
	return fmt.Errorf("flexible bool: unsupported value %s", string(data))
}

// CommaStrings is a []string that unmarshals from a JSON string (comma-separated) or a JSON array.
// Used for env vars like OIDC_SCOPES=openid,profile and YAML arrays.
type CommaStrings []string

// UnmarshalJSON implements json.Unmarshaler.
func (c *CommaStrings) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*c = nil
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*c = splitTrim(s, ",")
		return nil
	}
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*c = slice
	return nil
}

// Config holds configuration for accessgate-auth (loaded via go-config from file + env).
type Config struct {
	// OIDC
	OIDCIssuer       string       `json:"oidc_issuer"`
	OIDCRedirectURI  string       `json:"oidc_redirect_uri"`
	OIDCClientID     string       `json:"oidc_client_id"`
	OIDCClientSecret string       `json:"oidc_client_secret"`
	OIDCScopes       CommaStrings `json:"oidc_scopes"`
	OIDCAudience     string       `json:"oidc_audience"`
	OIDCClaimsSource string       `json:"oidc_claims_source"`

	// Redis
	RedisURL string `json:"redis_url"`

	// Session key layout and TTLs
	SessionRedisPrefix           string `json:"session_redis_prefix"`
	SessionTTLSeconds            int    `json:"session_ttl_seconds"`
	SessionPKCETTLSeconds        int    `json:"session_pkce_ttl_seconds"`
	SessionRefreshLockTTLSeconds int    `json:"session_refresh_lock_ttl_seconds"`
	SessionRefreshEarlySeconds   int    `json:"session_refresh_early_seconds"`

	// Cookie
	CookieName          string       `json:"cookie_name"`
	CookieSigningSecret string       `json:"cookie_signing_secret"`
	CookieSecure        FlexibleBool `json:"cookie_secure"`
	CookieSameSiteStr   string       `json:"cookie_same_site"`
	CookieDomain        string       `json:"cookie_domain"`
	// CookieSameSite is set in Validate() from CookieSameSiteStr.
	CookieSameSite http.SameSite `json:"-"`

	// App and redirects
	AppBaseURL             string       `json:"app_base_url"`
	LoginErrorRedirectPath string       `json:"login_error_redirect_path"`
	AllowedRedirectOrigins CommaStrings `json:"allowed_redirect_origins"`
	AllowedRedirectPaths   CommaStrings `json:"allowed_redirect_paths"`

	// HTTP
	HTTPPort string `json:"http_port"`

	// AdminSecret if set guards /admin and PATCH|POST /internal/session; requests must include header X-Admin-Secret: <value>. Empty disables those endpoints.
	AdminSecret string `json:"admin_secret"`

	// Optional: webhook and enrichment
	PostLoginWebhookURL  string `json:"post_login_webhook_url"`
	SessionEnrichmentAPI string `json:"session_enrichment_api"`

	// CORS
	CORSAllowedOrigins CommaStrings `json:"cors_allowed_origins"`

	// ProviderPluginID selects the identity provider plugin by ID or capability (e.g. "oidc", "provider:oidc"). Empty means use built-in OIDC from top-level config.
	ProviderPluginID string `json:"provider_plugin_id"`
}

// Validate returns an error if required configuration is missing.
// It also applies defaults and parses CookieSameSiteStr into CookieSameSite.
func (c *Config) Validate() error {
	if c.OIDCIssuer == "" {
		return errMissing("OIDC_ISSUER")
	}
	if c.OIDCRedirectURI == "" {
		return errMissing("OIDC_REDIRECT_URI")
	}
	if c.OIDCClientID == "" {
		return errMissing("OIDC_CLIENT_ID")
	}
	if c.RedisURL == "" {
		return errMissing("REDIS_URL")
	}
	if c.CookieSigningSecret == "" {
		return errMissing("COOKIE_SIGNING_SECRET")
	}
	if c.OIDCClientSecret == "your-client-secret" || c.CookieSigningSecret == "CHANGE-ME-in-production" {
		return fmt.Errorf("config: placeholder secret detected — set real secrets via environment variables")
	}
	if c.AppBaseURL == "" {
		return errMissing("APP_BASE_URL")
	}
	if c.OIDCClaimsSource != "id_token" && c.OIDCClaimsSource != "access_token" {
		c.OIDCClaimsSource = "id_token"
	}
	c.CookieSameSite = parseSameSite(c.CookieSameSiteStr)
	if len(c.OIDCScopes) == 0 {
		c.OIDCScopes = CommaStrings{"openid", "profile"}
	}
	if len(c.AllowedRedirectPaths) == 0 {
		c.AllowedRedirectPaths = CommaStrings{"/"}
	}
	return nil
}

// KeyLayout returns the session key layout for Redis.
func (c *Config) KeyLayout() session.KeyLayout {
	p := c.SessionRedisPrefix
	if p == "" {
		p = "auth"
	}
	return session.KeyLayout{
		SessionPrefix:         p + ":session:",
		PKCEPrefix:            p + ":pkce:",
		RefreshLockPrefix:     p + ":refresh_lock:",
		RevokedPrefix:         p + ":revoked:",
		ReplayPrefix:          p + ":replay:",
		SessionTTLSeconds:     c.SessionTTLSeconds,
		PKCETTLSeconds:        c.SessionPKCETTLSeconds,
		RefreshLockTTLSeconds: c.SessionRefreshLockTTLSeconds,
	}
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

type configError string

func (e configError) Error() string { return "config: missing " + string(e) }

func errMissing(name string) error { return configError(name) }

// ApplyDefaults sets default values for optional fields when not set.
// Call after Load from go-config if you need the same defaults as before (e.g. HTTP port).
func (c *Config) ApplyDefaults() {
	if c.OIDCClaimsSource == "" {
		c.OIDCClaimsSource = "id_token"
	}
	if c.SessionRedisPrefix == "" {
		c.SessionRedisPrefix = "auth"
	}
	if c.SessionTTLSeconds == 0 {
		c.SessionTTLSeconds = 36000
	}
	if c.SessionPKCETTLSeconds == 0 {
		c.SessionPKCETTLSeconds = 300
	}
	if c.SessionRefreshLockTTLSeconds == 0 {
		c.SessionRefreshLockTTLSeconds = 15
	}
	if c.SessionRefreshEarlySeconds == 0 {
		c.SessionRefreshEarlySeconds = 60
	}
	if c.CookieName == "" {
		c.CookieName = "__Host-ess_session"
	}
	if c.LoginErrorRedirectPath == "" {
		c.LoginErrorRedirectPath = "/login?error=oidc_error"
	}
	if c.HTTPPort == "" {
		c.HTTPPort = "8080"
	}
}

// OIDCScopesSlice returns OIDCScopes as []string for APIs that require it.
func (c *Config) OIDCScopesSlice() []string { return []string(c.OIDCScopes) }

// AllowedRedirectOriginsSlice returns AllowedRedirectOrigins as []string.
func (c *Config) AllowedRedirectOriginsSlice() []string { return []string(c.AllowedRedirectOrigins) }

// AllowedRedirectPathsSlice returns AllowedRedirectPaths as []string.
func (c *Config) AllowedRedirectPathsSlice() []string { return []string(c.AllowedRedirectPaths) }

// CORSAllowedOriginsSlice returns CORSAllowedOrigins as []string.
func (c *Config) CORSAllowedOriginsSlice() []string { return []string(c.CORSAllowedOrigins) }
