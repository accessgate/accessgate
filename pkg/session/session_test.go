package session

import (
	"testing"
	"time"
)

func TestDefaultKeyLayout(t *testing.T) {
	k := DefaultKeyLayout()
	if k.SessionPrefix == "" || k.PKCETTLSeconds <= 0 {
		t.Fatalf("unexpected layout: %+v", k)
	}
}

func TestKeyLayoutKeys(t *testing.T) {
	k := KeyLayout{
		SessionPrefix:     "s:",
		PKCEPrefix:        "p:",
		RefreshLockPrefix: "r:",
		RevokedPrefix:     "v:",
		ReplayPrefix:      "q:",
	}
	if got := k.SessionKey("a"); got != "s:a" {
		t.Fatal(got)
	}
	if got := k.PKCEKey("st"); got != "p:st" {
		t.Fatal(got)
	}
	if got := k.RefreshLockKey("x"); got != "r:x" {
		t.Fatal(got)
	}
	if got := k.RevokedKey("j"); got != "v:j" {
		t.Fatal(got)
	}
	if got := k.ReplayKey("n"); got != "q:n" {
		t.Fatal(got)
	}
}

func TestKeyLayoutRevokedReplayFallbackPrefix(t *testing.T) {
	k := KeyLayout{RevokedPrefix: "", ReplayPrefix: ""}
	if got := k.RevokedKey("id"); got != "auth:revoked:id" {
		t.Fatal(got)
	}
	if got := k.ReplayKey("k"); got != "auth:replay:k" {
		t.Fatal(got)
	}
}

func TestSessionExpiresAndRefresh(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &Session{ExpiresAt: 1000}
	if !s.IsExpired(now) {
		t.Fatal("expected expired at boundary")
	}
	if s.IsExpired(now.Add(-time.Second)) {
		t.Fatal("expected not expired")
	}
	s2 := &Session{ExpiresAt: 2000}
	if !s2.NeedsRefresh(time.Unix(1990, 0), 15) {
		t.Fatal("expected needs refresh within window")
	}
	if s2.NeedsRefresh(time.Unix(1000, 0), 15) {
		t.Fatal("unexpected needs refresh")
	}
	if s2.ExpiresAtTime().Unix() != 2000 {
		t.Fatal(s2.ExpiresAtTime())
	}
}
