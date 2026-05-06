package session

import (
	"context"
	"time"
)

// SessionStore persists and retrieves sessions (e.g. Redis).
//
// Revocation: To revoke a session (e.g. logout), call Delete(ctx, sessionID).
// For "logout everywhere" or token revocation, use a RevocationStore in addition to Delete.
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

// RevocationStore tracks revoked IDs (session IDs, JTIs, or equivalent runtime tokens).
type RevocationStore interface {
	SetRevoked(ctx context.Context, id string, ttl time.Duration) error
	IsRevoked(ctx context.Context, id string) (bool, error)
}

// ReplayStore tracks one-time or replay-sensitive keys such as request IDs or nonces.
type ReplayStore interface {
	RecordReplay(ctx context.Context, key string, ttl time.Duration) error
	CheckReplay(ctx context.Context, key string) (alreadySeen bool, err error)
}

// RuntimeStoreProvider exposes the minimum persistence seams the auth runtime needs.
type RuntimeStoreProvider interface {
	SessionStore() SessionStore
	PKCEStore() PKCEStore
	RefreshLockStore() RefreshLockStore
}

// ExtendedRuntimeStoreProvider exposes adjacent persistence seams that stay behind stable interfaces.
type ExtendedRuntimeStoreProvider interface {
	RuntimeStoreProvider
	RevocationStore() RevocationStore
	ReplayStore() ReplayStore
}
