// Package handoff implements a signed, one-time connector handoff ticket. It lets one
// connector flow (e.g. a Telegram bot that has completed OIDC) hand a browser into the
// corresponding web session without the fragile cookie -> edge-header glue: the ticket is
// HMAC-signed, short-lived, and redeemable exactly once (replay-protected server-side).
package handoff

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DefaultTTL is the lifetime of a handoff ticket when none is configured.
const DefaultTTL = 120 * time.Second

// Ticket is the signed handoff payload. Field names are short to keep tickets compact.
type Ticket struct {
	ConnectorID     string `json:"c"`
	AuthoritativeID string `json:"a"`
	SessionRef      string `json:"s"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
	JTI             string `json:"jti"`
}

// OnceStore atomically consumes a one-time key (the ticket JTI). firstUse is true exactly
// once per key within its TTL; later calls return false (replay). A Redis SETNX is the
// canonical implementation.
type OnceStore interface {
	ConsumeOnce(ctx context.Context, key string, ttl time.Duration) (firstUse bool, err error)
}

// Issuer issues and redeems signed handoff tickets.
type Issuer struct {
	secret []byte
	ttl    time.Duration
	once   OnceStore
	now    func() time.Time
}

// NewIssuer builds an Issuer signing with secret (reuse the cookie signing secret), tickets
// living for ttl, and once providing replay protection on redemption.
func NewIssuer(secret string, ttl time.Duration, once OnceStore) *Issuer {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Issuer{secret: []byte(secret), ttl: ttl, once: once, now: time.Now}
}

// Issue mints a signed ticket binding the connector, authoritative id, and session ref.
// jti must be a unique, unguessable id (the caller supplies cryptographic randomness).
func (i *Issuer) Issue(connectorID, authID, sessionRef, jti string) (string, error) {
	if sessionRef == "" || jti == "" {
		return "", fmt.Errorf("handoff: session ref and jti are required")
	}
	now := i.now()
	t := Ticket{
		ConnectorID:     connectorID,
		AuthoritativeID: authID,
		SessionRef:      sessionRef,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(i.ttl).Unix(),
		JTI:             jti,
	}
	payloadJSON, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	payload := base64.URLEncoding.EncodeToString(payloadJSON)
	sig := i.sign([]byte(payload))
	return payload + "." + base64.URLEncoding.EncodeToString(sig), nil
}

// Redeem verifies the ticket signature and expiry, then atomically consumes its JTI so it
// can be redeemed only once. It fails closed when the one-time store is unavailable.
func (i *Issuer) Redeem(ctx context.Context, ticket string) (*Ticket, error) {
	t, err := i.verify(ticket)
	if err != nil {
		return nil, err
	}
	if i.once == nil {
		return nil, fmt.Errorf("handoff: one-time store not configured")
	}
	ttl := time.Until(time.Unix(t.ExpiresAt, 0)) + time.Second
	if ttl <= 0 {
		ttl = time.Second
	}
	first, err := i.once.ConsumeOnce(ctx, "handoff:"+t.JTI, ttl)
	if err != nil {
		return nil, fmt.Errorf("handoff: replay check failed: %w", err)
	}
	if !first {
		return nil, fmt.Errorf("handoff: ticket already redeemed")
	}
	return t, nil
}

func (i *Issuer) verify(ticket string) (*Ticket, error) {
	parts := strings.SplitN(ticket, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("handoff: malformed ticket")
	}
	payload, sigB64 := parts[0], parts[1]
	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("handoff: bad signature encoding")
	}
	if !hmac.Equal(sig, i.sign([]byte(payload))) {
		return nil, fmt.Errorf("handoff: invalid signature")
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("handoff: bad payload encoding")
	}
	var t Ticket
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("handoff: bad payload")
	}
	if i.now().Unix() > t.ExpiresAt {
		return nil, fmt.Errorf("handoff: ticket expired")
	}
	return &t, nil
}

func (i *Issuer) sign(data []byte) []byte {
	h := hmac.New(sha256.New, i.secret)
	h.Write(data)
	return h.Sum(nil)
}
