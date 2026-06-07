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

// RuntimeStoreProvider exposes the minimum persistence seams the auth runtime needs
// (session, PKCE, refresh-lock). It is intentionally the narrow consumer interface the
// auth service depends on — keeping the service free of stores it does not use.
//
// RuntimeStoreProvider and ExtendedRuntimeStoreProvider are a deliberate
// interface-segregation pair, not a deprecation step: the narrow interface is what
// consumers depend on, while the extended one is the broader capability set that a
// concrete store (e.g. the Redis store) implements. Both are part of the frozen v1 API;
// new persistence seams are added on the extended interface, never on this one.
type RuntimeStoreProvider interface {
	SessionStore() SessionStore
	PKCEStore() PKCEStore
	RefreshLockStore() RefreshLockStore
}

// ExtendedRuntimeStoreProvider is the broader capability interface: the core runtime
// seams plus the adjacent revocation/replay seams. Concrete stores implement this; the
// split from RuntimeStoreProvider is intended (see that type's doc), not vestigial.
type ExtendedRuntimeStoreProvider interface {
	RuntimeStoreProvider
	RevocationStore() RevocationStore
	ReplayStore() ReplayStore
}
