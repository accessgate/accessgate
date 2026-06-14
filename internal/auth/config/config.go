package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/accessgate/accessgate/pkg/session"
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

	// Optional: webhook
	PostLoginWebhookURL string `json:"post_login_webhook_url"`

	// CORS
	CORSAllowedOrigins CommaStrings `json:"cors_allowed_origins"`

	// ProviderPluginID selects the identity provider plugin by ID or capability (e.g. "oidc", "provider:oidc"). Empty means use built-in OIDC from top-level config.
	ProviderPluginID string `json:"provider_plugin_id"`

	// Connectors lists the identity connectors hosted by this auth instance. When empty,
	// Normalize() synthesizes a single "default" connector from the legacy top-level OIDC
	// fields above, preserving the existing session prefix and cookie name (backward compat).
	Connectors []ConnectorConfig `json:"connectors"`
}

// ConnectorConfig describes a single identity connector hosted by accessgate-auth.
// Multiple connectors run inside one auth instance, each with its own OIDC client,
// session/PKCE namespace, cookie, and claim-mapping policy.
type ConnectorConfig struct {
	// ID is the URL-safe connector identifier used in path segments (/login/{connector}).
	ID string `json:"id"`
	// Default marks the connector selected when no connector is given (legacy /login).
	Default FlexibleBool `json:"default"`
	// ProviderPluginID selects the provider plugin for this connector (default "provider:oidc").
	ProviderPluginID string `json:"provider_plugin_id"`

	// OIDC client configuration for this connector.
	OIDCIssuer       string       `json:"oidc_issuer"`
	OIDCRedirectURI  string       `json:"oidc_redirect_uri"`
	OIDCClientID     string       `json:"oidc_client_id"`
	OIDCClientSecret string       `json:"oidc_client_secret"`
	OIDCScopes       CommaStrings `json:"oidc_scopes"`
	OIDCAudience     string       `json:"oidc_audience"`
	OIDCClaimsSource string       `json:"oidc_claims_source"`

	// SessionRedisPrefix namespaces this connector's Redis keys. Defaults to the
	// top-level prefix for the default connector, else "<base>:<id>".
	SessionRedisPrefix string `json:"session_redis_prefix"`
	// CookieName is this connector's session cookie. Defaults to the legacy cookie for
	// the default connector, else "<legacy>_<id>" (still keeps the __Host- prefix).
	CookieName string `json:"cookie_name"`

	// Per-connector TTL overrides; zero values fall back to the top-level session TTLs.
	SessionTTLSeconds            int `json:"session_ttl_seconds"`
	SessionPKCETTLSeconds        int `json:"session_pkce_ttl_seconds"`
	SessionRefreshLockTTLSeconds int `json:"session_refresh_lock_ttl_seconds"`

	// ClaimMapping controls how IdP claims become the authoritative downstream identity.
	ClaimMapping ClaimMappingConfig `json:"claim_mapping"`
}

// ClaimMappingConfig is a per-connector contract for normalizing IdP claims into the
// authoritative downstream identity. It lets connectors choose a provider-specific id
// (e.g. a Telegram numeric id) instead of always overloading the OIDC "sub".
type ClaimMappingConfig struct {
	// AuthoritativeIDClaim names the claim used as the downstream identity (default "sub").
	AuthoritativeIDClaim string `json:"authoritative_id_claim"`
	// IDKind is a low-cardinality label for the id source (e.g. "oidc_sub", "telegram_id").
	IDKind string `json:"id_kind"`
	// Optional claim overrides for derived headers; empty uses the standard OIDC claims.
	EmailClaim string `json:"email_claim"`
	NameClaim  string `json:"name_claim"`
	RolesClaim string `json:"roles_claim"`
}

// Validate returns an error if required configuration is missing.
// It also applies defaults and parses CookieSameSiteStr into CookieSameSite.
//
// When Connectors is empty it validates the legacy single-provider top-level OIDC fields
// (so existing configs and callers that invoke Validate() without Normalize() keep working).
// When Connectors is non-empty it validates each connector instead.
func (c *Config) Validate() error {
	// Shared, always-required fields.
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
	c.CookieSameSite = parseSameSite(c.CookieSameSiteStr)
	if len(c.AllowedRedirectPaths) == 0 {
		c.AllowedRedirectPaths = CommaStrings{"/"}
	}

	if len(c.Connectors) == 0 {
		// Legacy single-provider mode.
		if c.OIDCIssuer == "" {
			return errMissing("OIDC_ISSUER")
		}
		if c.OIDCRedirectURI == "" {
			return errMissing("OIDC_REDIRECT_URI")
		}
		if c.OIDCClientID == "" {
			return errMissing("OIDC_CLIENT_ID")
		}
		if c.OIDCClaimsSource != "id_token" && c.OIDCClaimsSource != "access_token" {
			c.OIDCClaimsSource = "id_token"
		}
		if len(c.OIDCScopes) == 0 {
			c.OIDCScopes = CommaStrings{"openid", "profile"}
		}
		return nil
	}
	return c.validateConnectors()
}

// connectorIDRe restricts connector ids to URL-safe path segments.
var connectorIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validateConnectors validates the multi-connector configuration. It assumes
// Normalize() has already filled per-connector defaults.
func (c *Config) validateConnectors() error {
	seen := make(map[string]bool, len(c.Connectors))
	defaults := 0
	for i := range c.Connectors {
		conn := &c.Connectors[i]
		if conn.ID == "" {
			return fmt.Errorf("config: connector[%d] missing id", i)
		}
		if !connectorIDRe.MatchString(conn.ID) {
			return fmt.Errorf("config: connector id %q must match [A-Za-z0-9_-]+", conn.ID)
		}
		if seen[conn.ID] {
			return fmt.Errorf("config: duplicate connector id %q", conn.ID)
		}
		seen[conn.ID] = true
		if bool(conn.Default) {
			defaults++
		}
		if conn.OIDCIssuer == "" {
			return fmt.Errorf("config: connector %q missing oidc_issuer", conn.ID)
		}
		if conn.OIDCRedirectURI == "" {
			return fmt.Errorf("config: connector %q missing oidc_redirect_uri", conn.ID)
		}
		if conn.OIDCClientID == "" {
			return fmt.Errorf("config: connector %q missing oidc_client_id", conn.ID)
		}
	}
	if defaults != 1 {
		return fmt.Errorf("config: exactly one connector must be marked default (found %d)", defaults)
	}
	return nil
}

// Normalize synthesizes and fills defaults for the connector list. When no connectors are
// configured it creates a single "default" connector from the legacy top-level OIDC fields,
// preserving the existing Redis prefix and cookie name. It is idempotent and should be called
// after ApplyDefaults() and before Validate() (Load does this). Direct callers of Validate()
// that skip Normalize() get legacy single-provider validation.
func (c *Config) Normalize() {
	if len(c.Connectors) == 0 {
		c.Connectors = []ConnectorConfig{{
			ID:               "default",
			Default:          true,
			ProviderPluginID: c.ProviderPluginID,
			OIDCIssuer:       c.OIDCIssuer,
			OIDCRedirectURI:  c.OIDCRedirectURI,
			OIDCClientID:     c.OIDCClientID,
			OIDCClientSecret: c.OIDCClientSecret,
			OIDCScopes:       c.OIDCScopes,
			OIDCAudience:     c.OIDCAudience,
			OIDCClaimsSource: c.OIDCClaimsSource,
		}}
	}
	// A single connector is implicitly the default.
	if len(c.Connectors) == 1 {
		c.Connectors[0].Default = true
	}
	base := c.SessionRedisPrefix
	if base == "" {
		base = "auth"
	}
	legacyCookie := c.CookieName
	if legacyCookie == "" {
		legacyCookie = "__Host-ess_session"
	}
	for i := range c.Connectors {
		conn := &c.Connectors[i]
		if conn.ProviderPluginID == "" {
			conn.ProviderPluginID = c.ProviderPluginID
		}
		if len(conn.OIDCScopes) == 0 {
			conn.OIDCScopes = CommaStrings{"openid", "profile"}
		}
		if conn.OIDCClaimsSource != "id_token" && conn.OIDCClaimsSource != "access_token" {
			conn.OIDCClaimsSource = "id_token"
		}
		if conn.SessionRedisPrefix == "" {
			if bool(conn.Default) {
				conn.SessionRedisPrefix = base
			} else {
				conn.SessionRedisPrefix = base + ":" + conn.ID
			}
		}
		if conn.CookieName == "" {
			if bool(conn.Default) {
				conn.CookieName = legacyCookie
			} else {
				conn.CookieName = legacyCookie + "_" + conn.ID
			}
		}
		if conn.SessionTTLSeconds == 0 {
			conn.SessionTTLSeconds = c.SessionTTLSeconds
		}
		if conn.SessionPKCETTLSeconds == 0 {
			conn.SessionPKCETTLSeconds = c.SessionPKCETTLSeconds
		}
		if conn.SessionRefreshLockTTLSeconds == 0 {
			conn.SessionRefreshLockTTLSeconds = c.SessionRefreshLockTTLSeconds
		}
		if conn.ClaimMapping.AuthoritativeIDClaim == "" {
			conn.ClaimMapping.AuthoritativeIDClaim = "sub"
		}
		if conn.ClaimMapping.IDKind == "" {
			if conn.ClaimMapping.AuthoritativeIDClaim == "sub" {
				conn.ClaimMapping.IDKind = "oidc_sub"
			} else {
				conn.ClaimMapping.IDKind = conn.ID
			}
		}
	}
}

// ConnectorByID returns the connector with the given id (empty id = default). It falls back
// to the default connector when the id is unknown, and nil only when no connectors exist
// (config not yet normalized).
func (c *Config) ConnectorByID(id string) *ConnectorConfig {
	if id == "" {
		return c.DefaultConnector()
	}
	for i := range c.Connectors {
		if c.Connectors[i].ID == id {
			return &c.Connectors[i]
		}
	}
	return c.DefaultConnector()
}

// DefaultConnector returns the connector marked default, or the first connector.
// Returns nil only when no connectors are configured (Normalize not yet called).
func (c *Config) DefaultConnector() *ConnectorConfig {
	for i := range c.Connectors {
		if bool(c.Connectors[i].Default) {
			return &c.Connectors[i]
		}
	}
	if len(c.Connectors) > 0 {
		return &c.Connectors[0]
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

// KeyLayout returns the session key layout for this connector's Redis namespace.
func (cc ConnectorConfig) KeyLayout() session.KeyLayout {
	p := cc.SessionRedisPrefix
	if p == "" {
		p = "auth"
	}
	return session.KeyLayout{
		SessionPrefix:         p + ":session:",
		PKCEPrefix:            p + ":pkce:",
		RefreshLockPrefix:     p + ":refresh_lock:",
		RevokedPrefix:         p + ":revoked:",
		ReplayPrefix:          p + ":replay:",
		SessionTTLSeconds:     cc.SessionTTLSeconds,
		PKCETTLSeconds:        cc.SessionPKCETTLSeconds,
		RefreshLockTTLSeconds: cc.SessionRefreshLockTTLSeconds,
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
