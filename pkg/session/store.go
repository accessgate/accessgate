package session

import "context"

// SessionStore persists and retrieves sessions (e.g. Redis).
//
// Revocation: To revoke a session (e.g. logout), call Delete(ctx, sessionID).
// For "logout everywhere" or token revocation, use a revocation list (e.g. internal/store/redis
// SetRevoked/IsRevoked) in addition to Delete.
type SessionStore interface {
	Get(ctx context.Context, sessionID string) (*Session, error)
	Set(ctx context.Context, sessionID string, s *Session, ttlSeconds int) error
	Delete(ctx context.Context, sessionID string) error
}

// PKCEStore persists and retrieves PKCE state (e.g. Redis).
type PKCEStore interface {
	Get(ctx context.Context, state string) (*PKCEState, error)
	Set(ctx context.Context, state string, p *PKCEState, ttlSeconds int) error
	Delete(ctx context.Context, state string) error
}

// RefreshLockStore provides a short-lived lock per session to avoid concurrent refresh.
type RefreshLockStore interface {
	Obtain(ctx context.Context, sessionID string, ttlSeconds int) (bool, error) // true if lock acquired
	Release(ctx context.Context, sessionID string) error
}
