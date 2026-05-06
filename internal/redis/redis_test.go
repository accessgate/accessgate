// Package redis tests require a running Redis. Set REDIS_URL (e.g. redis://localhost:6379/1) to run them.
// In CI, provide REDIS_URL or use testcontainers to start Redis for integration tests.
package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ArmanAvanesyan/accessgate/pkg/session"
)

var (
	_ session.RuntimeStoreProvider         = (*Store)(nil)
	_ session.ExtendedRuntimeStoreProvider = (*Store)(nil)
)

func TestSessionSetGetDelete(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/2"
	}
	ctx := context.Background()
	layout := session.DefaultKeyLayout()
	store, err := New(ctx, url, layout, nil)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("redis close: %v", err)
		}
	}()

	sessStore := store.SessionStore()
	sessionID := "session-integration-test-1"
	sess := &session.Session{
		ID:           sessionID,
		AccessToken:  "at",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Claims:       map[string]any{"sub": "user-1"},
	}
	if err := sessStore.Set(ctx, sessionID, sess, 60); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := sessStore.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.ID != sessionID || got.Claims["sub"] != "user-1" {
		t.Fatalf("Get: got %+v", got)
	}
	if err := sessStore.Delete(ctx, sessionID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err = sessStore.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil after Delete, got %+v", got)
	}
}

func TestRevocationStoreAccessor(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/1"
	}
	ctx := context.Background()
	layout := session.DefaultKeyLayout()
	store, err := New(ctx, url, layout, nil)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("redis close: %v", err)
		}
	}()

	revocations := store.RevocationStore()
	if revocations == nil {
		t.Fatal("expected revocation store accessor")
	}

	id := "revocation-accessor-test-123"
	if err := revocations.SetRevoked(ctx, id, 10*time.Second); err != nil {
		t.Fatalf("SetRevoked via accessor: %v", err)
	}
	ok, err := revocations.IsRevoked(ctx, id)
	if err != nil {
		t.Fatalf("IsRevoked via accessor: %v", err)
	}
	if !ok {
		t.Fatal("expected revoked via accessor")
	}
}

func TestSetRevokedAndIsRevoked(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/1"
	}
	ctx := context.Background()
	layout := session.DefaultKeyLayout()
	store, err := New(ctx, url, layout, nil)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("redis close: %v", err)
		}
	}()

	id := "jti-revoked-test-123"
	ttl := 10 * time.Second

	revoked, err := store.IsRevoked(ctx, id)
	if err != nil {
		t.Fatalf("IsRevoked (before): %v", err)
	}
	if revoked {
		t.Fatal("expected not revoked before SetRevoked")
	}

	if err := store.SetRevoked(ctx, id, ttl); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}

	revoked, err = store.IsRevoked(ctx, id)
	if err != nil {
		t.Fatalf("IsRevoked (after): %v", err)
	}
	if !revoked {
		t.Fatal("expected revoked after SetRevoked")
	}
}

func TestReplayStoreAccessor(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/1"
	}
	ctx := context.Background()
	layout := session.DefaultKeyLayout()
	store, err := New(ctx, url, layout, nil)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("redis close: %v", err)
		}
	}()

	replays := store.ReplayStore()
	if replays == nil {
		t.Fatal("expected replay store accessor")
	}

	key := "replay-accessor-unique-456"
	if err := replays.RecordReplay(ctx, key, 5*time.Second); err != nil {
		t.Fatalf("RecordReplay via accessor: %v", err)
	}
	seen, err := replays.CheckReplay(ctx, key)
	if err != nil {
		t.Fatalf("CheckReplay via accessor: %v", err)
	}
	if !seen {
		t.Fatal("expected seen via accessor")
	}
}

func TestCheckReplayAndRecordReplay(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/1"
	}
	ctx := context.Background()
	layout := session.DefaultKeyLayout()
	store, err := New(ctx, url, layout, nil)
	if err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("redis close: %v", err)
		}
	}()

	key := "replay-key-unique-456"
	ttl := 5 * time.Second

	seen, err := store.CheckReplay(ctx, key)
	if err != nil {
		t.Fatalf("CheckReplay (before): %v", err)
	}
	if seen {
		t.Fatal("expected not seen before RecordReplay")
	}

	if err := store.RecordReplay(ctx, key, ttl); err != nil {
		t.Fatalf("RecordReplay: %v", err)
	}

	seen, err = store.CheckReplay(ctx, key)
	if err != nil {
		t.Fatalf("CheckReplay (after): %v", err)
	}
	if !seen {
		t.Fatal("expected seen after RecordReplay")
	}
}
