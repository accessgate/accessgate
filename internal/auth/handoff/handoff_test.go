package handoff

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeOnce struct {
	seen map[string]bool
	err  error
}

func newFakeOnce() *fakeOnce { return &fakeOnce{seen: map[string]bool{}} }

func (f *fakeOnce) ConsumeOnce(_ context.Context, key string, _ time.Duration) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

func TestIssueRedeem_HappyPath(t *testing.T) {
	once := newFakeOnce()
	i := NewIssuer("secret", time.Minute, once)
	ticket, err := i.Issue("telegram", "555", "sess-1", "jti-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tk, err := i.Redeem(context.Background(), ticket)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if tk.ConnectorID != "telegram" || tk.AuthoritativeID != "555" || tk.SessionRef != "sess-1" {
		t.Fatalf("unexpected ticket: %+v", tk)
	}
}

func TestRedeem_RejectsReplay(t *testing.T) {
	once := newFakeOnce()
	i := NewIssuer("secret", time.Minute, once)
	ticket, _ := i.Issue("c", "a", "sess-1", "jti-1")
	if _, err := i.Redeem(context.Background(), ticket); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := i.Redeem(context.Background(), ticket); err == nil {
		t.Fatal("expected replay rejection on second redeem")
	}
}

func TestRedeem_RejectsTampered(t *testing.T) {
	i := NewIssuer("secret", time.Minute, newFakeOnce())
	ticket, _ := i.Issue("c", "a", "sess-1", "jti-1")
	// Flip a character in the payload.
	tampered := "Z" + ticket[1:]
	if _, err := i.Redeem(context.Background(), tampered); err == nil {
		t.Fatal("expected signature rejection for tampered ticket")
	}
	// Wrong secret cannot verify a valid ticket.
	other := NewIssuer("different", time.Minute, newFakeOnce())
	if _, err := other.Redeem(context.Background(), ticket); err == nil {
		t.Fatal("expected signature rejection across secrets")
	}
}

func TestRedeem_RejectsExpired(t *testing.T) {
	i := NewIssuer("secret", time.Minute, newFakeOnce())
	base := time.Unix(1_700_000_000, 0)
	i.now = func() time.Time { return base }
	ticket, _ := i.Issue("c", "a", "sess-1", "jti-1")
	// Advance past expiry.
	i.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := i.Redeem(context.Background(), ticket); err == nil {
		t.Fatal("expected expired ticket rejection")
	}
}

func TestRedeem_FailsClosedWhenStoreDown(t *testing.T) {
	// No once store configured.
	i := NewIssuer("secret", time.Minute, nil)
	ticket, _ := i.Issue("c", "a", "sess-1", "jti-1")
	if _, err := i.Redeem(context.Background(), ticket); err == nil {
		t.Fatal("expected failure when one-time store is not configured")
	}
	// Once store returning an error must fail closed too.
	bad := &fakeOnce{seen: map[string]bool{}, err: errors.New("redis down")}
	i2 := NewIssuer("secret", time.Minute, bad)
	ticket2, _ := i2.Issue("c", "a", "sess-1", "jti-2")
	if _, err := i2.Redeem(context.Background(), ticket2); err == nil {
		t.Fatal("expected failure when one-time store errors")
	}
}
