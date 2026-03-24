package session

import "time"

// Session holds the server-side session state (tokens and claims).
type Session struct {
	ID            string         `json:"id"`
	AccessToken   string         `json:"access_token"`
	RefreshToken  string         `json:"refresh_token,omitempty"`
	IDToken       string         `json:"id_token,omitempty"`
	ExpiresAt     int64          `json:"expires_at"` // Unix seconds
	Claims        map[string]any `json:"claims"`
	TenantContext *TenantContext `json:"tenant_context,omitempty"`
}

// TenantContext holds optional multi-tenant context (PeopleSuite).
type TenantContext struct {
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug,omitempty"`
	Status     string `json:"status,omitempty"`
	Locale     string `json:"locale,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
}

// KeyLayout defines Redis key prefixes and TTLs (configurable at runtime).
type KeyLayout struct {
	SessionPrefix         string // e.g. "auth:session:"
	PKCEPrefix            string // e.g. "auth:pkce:"
	RefreshLockPrefix     string // e.g. "auth:refresh_lock:"
	RevokedPrefix         string // e.g. "auth:revoked:" for JTI/session revocation
	ReplayPrefix          string // e.g. "auth:replay:" for optional replay cache
	SessionTTLSeconds     int    // e.g. 36000
	PKCETTLSeconds        int    // e.g. 300
	RefreshLockTTLSeconds int    // e.g. 15
}

// DefaultKeyLayout returns a default key layout.
func DefaultKeyLayout() KeyLayout {
	return KeyLayout{
		SessionPrefix:         "auth:session:",
		PKCEPrefix:            "auth:pkce:",
		RefreshLockPrefix:     "auth:refresh_lock:",
		RevokedPrefix:         "auth:revoked:",
		ReplayPrefix:          "auth:replay:",
		SessionTTLSeconds:     36000,
		PKCETTLSeconds:        300,
		RefreshLockTTLSeconds: 15,
	}
}

// SessionKey returns the Redis key for a session ID.
func (k KeyLayout) SessionKey(sessionID string) string {
	return k.SessionPrefix + sessionID
}

// PKCEKey returns the Redis key for a PKCE state.
func (k KeyLayout) PKCEKey(state string) string {
	return k.PKCEPrefix + state
}

// RefreshLockKey returns the Redis key for a refresh lock.
func (k KeyLayout) RefreshLockKey(sessionID string) string {
	return k.RefreshLockPrefix + sessionID
}

// RevokedKey returns the Redis key for a revoked JTI or session ID.
func (k KeyLayout) RevokedKey(id string) string {
	if k.RevokedPrefix == "" {
		return "auth:revoked:" + id
	}
	return k.RevokedPrefix + id
}

// ReplayKey returns the Redis key for a replay cache entry (request ID / nonce).
func (k KeyLayout) ReplayKey(key string) string {
	if k.ReplayPrefix == "" {
		return "auth:replay:" + key
	}
	return k.ReplayPrefix + key
}

// ExpiresAtTime returns session expiry as time.Time.
func (s *Session) ExpiresAtTime() time.Time {
	return time.Unix(s.ExpiresAt, 0)
}

// IsExpired returns true if the access token is past expiry (with no buffer).
func (s *Session) IsExpired(now time.Time) bool {
	return s.ExpiresAt <= now.Unix()
}

// NeedsRefresh returns true if the access token expires within refreshEarlySeconds.
func (s *Session) NeedsRefresh(now time.Time, refreshEarlySeconds int) bool {
	return s.ExpiresAt-int64(refreshEarlySeconds) <= now.Unix()
}
