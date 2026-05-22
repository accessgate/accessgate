package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ArmanAvanesyan/accessgate/pkg/observability"
	"github.com/ArmanAvanesyan/accessgate/pkg/session"
	"github.com/redis/go-redis/v9"
)

// Store implements SessionStore, PKCEStore, and RefreshLockStore using Redis.
type Store struct {
	client  *redis.Client
	layout  session.KeyLayout
	metrics observability.Metrics
}

// New creates a Redis store. url is e.g. "redis://localhost:6379/0".
func New(ctx context.Context, url string, layout session.KeyLayout, metrics observability.Metrics) (*Store, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	if metrics == nil {
		metrics = observability.NopMetrics{}
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Store{client: client, layout: layout, metrics: metrics}, nil
}

// Close closes the Redis client.
func (s *Store) Close() error {
	return s.client.Close()
}

// Ping checks connectivity to Redis. Used for readiness and admin health.
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// SessionStore returns a session.SessionStore implemented by this Store.
func (s *Store) SessionStore() session.SessionStore { return (*sessionStoreImpl)(s) }

// PKCEStore returns a session.PKCEStore implemented by this Store.
func (s *Store) PKCEStore() session.PKCEStore { return (*pkceStoreImpl)(s) }

// RefreshLockStore returns a session.RefreshLockStore implemented by this Store.
func (s *Store) RefreshLockStore() session.RefreshLockStore { return (*refreshLockStoreImpl)(s) }

// RevocationStore returns a session.RevocationStore implemented by this Store.
func (s *Store) RevocationStore() session.RevocationStore { return (*revocationStoreImpl)(s) }

// ReplayStore returns a session.ReplayStore implemented by this Store.
func (s *Store) ReplayStore() session.ReplayStore { return (*replayStoreImpl)(s) }

type sessionStoreImpl Store

func (s *sessionStoreImpl) Get(ctx context.Context, sessionID string) (*session.Session, error) {
	return (*Store)(s).getSession(ctx, sessionID)
}
func (s *sessionStoreImpl) Set(ctx context.Context, sessionID string, sess *session.Session, ttlSeconds int) error {
	return (*Store)(s).setSession(ctx, sessionID, sess, ttlSeconds)
}
func (s *sessionStoreImpl) Delete(ctx context.Context, sessionID string) error {
	return (*Store)(s).deleteSession(ctx, sessionID)
}

func (s *Store) getSession(ctx context.Context, sessionID string) (*session.Session, error) {
	key := s.layout.SessionKey(sessionID)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			s.metrics.SessionStoreOp("session_get", true)
			return nil, nil
		}
		s.metrics.SessionStoreOp("session_get", false)
		return nil, err
	}
	var sess session.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		s.metrics.SessionStoreOp("session_get", false)
		return nil, err
	}
	s.metrics.SessionStoreOp("session_get", true)
	return &sess, nil
}

// FindSessionBySubjectEmail scans active session records and returns the first
// non-expired session whose claims match the trusted subject/email pair.
func (s *Store) FindSessionBySubjectEmail(ctx context.Context, subject, email string) (*session.Session, error) {
	subject = strings.TrimSpace(subject)
	email = strings.TrimSpace(strings.ToLower(email))
	if subject == "" || email == "" {
		return nil, nil
	}

	pattern := s.layout.SessionPrefix + "*"
	var cursor uint64
	now := time.Now()

	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				return nil, err
			}
			var sess session.Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}
			if sess.IsExpired(now) {
				continue
			}
			if strings.TrimSpace(claimString(sess.Claims, "sub")) != subject {
				continue
			}
			if strings.TrimSpace(strings.ToLower(claimString(sess.Claims, "email"))) != email {
				continue
			}
			return &sess, nil
		}
		if next == 0 {
			break
		}
		cursor = next
	}

	return nil, nil
}

// DeleteSessionsBySubjectEmail scans active session records and deletes every
// non-expired session whose claims match the trusted subject/email pair.
func (s *Store) DeleteSessionsBySubjectEmail(ctx context.Context, subject, email string) (int, error) {
	subject = strings.TrimSpace(subject)
	email = strings.TrimSpace(strings.ToLower(email))
	if subject == "" || email == "" {
		return 0, nil
	}

	pattern := s.layout.SessionPrefix + "*"
	var cursor uint64
	now := time.Now()
	deleted := 0

	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return deleted, err
		}
		for _, key := range keys {
			data, err := s.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				return deleted, err
			}
			var sess session.Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}
			if sess.IsExpired(now) {
				continue
			}
			if strings.TrimSpace(claimString(sess.Claims, "sub")) != subject {
				continue
			}
			if strings.TrimSpace(strings.ToLower(claimString(sess.Claims, "email"))) != email {
				continue
			}
			if err := s.deleteSession(ctx, sess.ID); err != nil {
				return deleted, err
			}
			deleted++
		}
		if next == 0 {
			break
		}
		cursor = next
	}

	return deleted, nil
}

func claimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	v, _ := claims[key].(string)
	return v
}

func (s *Store) setSession(ctx context.Context, sessionID string, sess *session.Session, ttlSeconds int) error {
	key := s.layout.SessionKey(sessionID)
	data, err := json.Marshal(sess)
	if err != nil {
		s.metrics.SessionStoreOp("session_set", false)
		return err
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		s.metrics.SessionStoreOp("session_set", false)
		return err
	}
	s.metrics.SessionStoreOp("session_set", true)
	return nil
}
func (s *Store) deleteSession(ctx context.Context, sessionID string) error {
	if err := s.client.Del(ctx, s.layout.SessionKey(sessionID)).Err(); err != nil {
		s.metrics.SessionStoreOp("session_del", false)
		return err
	}
	s.metrics.SessionStoreOp("session_del", true)
	return nil
}

type pkceStoreImpl Store

func (s *pkceStoreImpl) Get(ctx context.Context, state string) (*session.PKCEState, error) {
	return (*Store)(s).getPKCE(ctx, state)
}
func (s *pkceStoreImpl) Set(ctx context.Context, state string, p *session.PKCEState, ttlSeconds int) error {
	return (*Store)(s).setPKCE(ctx, state, p, ttlSeconds)
}
func (s *pkceStoreImpl) Delete(ctx context.Context, state string) error {
	return (*Store)(s).deletePKCE(ctx, state)
}

func (s *Store) getPKCE(ctx context.Context, state string) (*session.PKCEState, error) {
	key := s.layout.PKCEKey(state)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			s.metrics.SessionStoreOp("pkce_get", true)
			return nil, nil
		}
		s.metrics.SessionStoreOp("pkce_get", false)
		return nil, err
	}
	var p session.PKCEState
	if err := json.Unmarshal(data, &p); err != nil {
		s.metrics.SessionStoreOp("pkce_get", false)
		return nil, err
	}
	s.metrics.SessionStoreOp("pkce_get", true)
	return &p, nil
}
func (s *Store) setPKCE(ctx context.Context, state string, p *session.PKCEState, ttlSeconds int) error {
	key := s.layout.PKCEKey(state)
	data, err := json.Marshal(p)
	if err != nil {
		s.metrics.SessionStoreOp("pkce_set", false)
		return err
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		s.metrics.SessionStoreOp("pkce_set", false)
		return err
	}
	s.metrics.SessionStoreOp("pkce_set", true)
	return nil
}
func (s *Store) deletePKCE(ctx context.Context, state string) error {
	if err := s.client.Del(ctx, s.layout.PKCEKey(state)).Err(); err != nil {
		s.metrics.SessionStoreOp("pkce_del", false)
		return err
	}
	s.metrics.SessionStoreOp("pkce_del", true)
	return nil
}

type refreshLockStoreImpl Store

func (s *refreshLockStoreImpl) Obtain(ctx context.Context, sessionID string, ttlSeconds int) (bool, error) {
	return (*Store)(s).obtainRefreshLock(ctx, sessionID, ttlSeconds)
}
func (s *refreshLockStoreImpl) Release(ctx context.Context, sessionID string) error {
	return (*Store)(s).releaseRefreshLock(ctx, sessionID)
}

func (s *Store) obtainRefreshLock(ctx context.Context, sessionID string, ttlSeconds int) (bool, error) {
	key := s.layout.RefreshLockKey(sessionID)
	ttl := time.Duration(ttlSeconds) * time.Second
	result, err := s.client.SetArgs(ctx, key, "1", redis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	acquired := result == "OK"
	if err != nil {
		s.metrics.SessionStoreOp("refresh_lock_obtain", false)
		return false, err
	}
	s.metrics.SessionStoreOp("refresh_lock_obtain", acquired)
	return acquired, nil
}
func (s *Store) releaseRefreshLock(ctx context.Context, sessionID string) error {
	if err := s.client.Del(ctx, s.layout.RefreshLockKey(sessionID)).Err(); err != nil {
		s.metrics.SessionStoreOp("refresh_lock_release", false)
		return err
	}
	s.metrics.SessionStoreOp("refresh_lock_release", true)
	return nil
}

// SetRevoked marks the given id (JTI or session ID) as revoked for the given TTL.
// Used for logout-all and token revocation.
type revocationStoreImpl Store

func (s *revocationStoreImpl) SetRevoked(ctx context.Context, id string, ttl time.Duration) error {
	return (*Store)(s).SetRevoked(ctx, id, ttl)
}

func (s *revocationStoreImpl) IsRevoked(ctx context.Context, id string) (bool, error) {
	return (*Store)(s).IsRevoked(ctx, id)
}

func (s *Store) SetRevoked(ctx context.Context, id string, ttl time.Duration) error {
	key := s.layout.RevokedKey(id)
	return s.client.Set(ctx, key, "1", ttl).Err()
}

// IsRevoked returns true if the id has been revoked (and the entry has not yet expired).
func (s *Store) IsRevoked(ctx context.Context, id string) (bool, error) {
	key := s.layout.RevokedKey(id)
	_, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RecordReplay records a key (e.g. request ID or nonce) in the replay cache with the given TTL.
// Returns nil on success.
type replayStoreImpl Store

func (s *replayStoreImpl) RecordReplay(ctx context.Context, key string, ttl time.Duration) error {
	return (*Store)(s).RecordReplay(ctx, key, ttl)
}

func (s *replayStoreImpl) CheckReplay(ctx context.Context, key string) (bool, error) {
	return (*Store)(s).CheckReplay(ctx, key)
}

func (s *Store) RecordReplay(ctx context.Context, key string, ttl time.Duration) error {
	k := s.layout.ReplayKey(key)
	return s.client.Set(ctx, k, "1", ttl).Err()
}

// CheckReplay returns true if the key was already seen (replay), and false if not yet seen.
// Does not record the key; use RecordReplay after validating to record.
func (s *Store) CheckReplay(ctx context.Context, key string) (alreadySeen bool, err error) {
	k := s.layout.ReplayKey(key)
	_, err = s.client.Get(ctx, k).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
