package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

var ErrInvalidSignature = errors.New("cookie: invalid signature")

const signedSep = "."

// SignedManager implements Manager with HMAC-SHA256 signed values (session ID only).
// Only parties with the same secret can create or validate cookies.
type SignedManager struct {
	primary []byte   // used for signing and first verify attempt
	older   [][]byte // optional older secrets for key rotation (verify only)
}

// NewSignedManager returns a Manager that signs and verifies cookie values with the given secret.
func NewSignedManager(secret string) *SignedManager {
	return &SignedManager{primary: []byte(secret)}
}

// NewSignedManagerWithKeys returns a Manager that signs with primary and verifies with primary or any older secret.
// Use for key rotation: after rotating, pass the new secret as primary and the previous as older.
func NewSignedManagerWithKeys(primary string, older ...string) *SignedManager {
	olderBytes := make([][]byte, len(older))
	for i, s := range older {
		olderBytes[i] = []byte(s)
	}
	return &SignedManager{primary: []byte(primary), older: olderBytes}
}

// SignedCodec adapts SignedManager to the Codec interface.
type SignedCodec struct {
	m *SignedManager
}

// NewSignedCodec wraps a SignedManager as a Codec.
func NewSignedCodec(m *SignedManager) Codec {
	return SignedCodec{m: m}
}

// Encode encodes the given session ID using the underlying SignedManager.
func (s SignedCodec) Encode(sessionID string) (string, error) {
	return s.m.Encode(sessionID)
}

// Decode decodes the given raw cookie value into a session ID.
func (s SignedCodec) Decode(raw string) (string, error) {
	var id string
	if err := s.m.Decode(raw, &id); err != nil {
		return "", err
	}
	return id, nil
}

// Encode signs v (expected to be a string session ID) and returns a cookie-safe value.
// Signing uses the primary secret.
func (m *SignedManager) Encode(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", nil
	}
	payload := base64.URLEncoding.EncodeToString([]byte(s))
	sig := m.signWith(m.primary, []byte(payload))
	return payload + signedSep + base64.URLEncoding.EncodeToString(sig), nil
}

// Decode verifies the signature (using primary or any older key) and decodes the session ID into dst (must be *string).
// Returns ErrInvalidSignature when the value is malformed or the signature does not match.
func (m *SignedManager) Decode(raw string, dst any) error {
	parts := strings.SplitN(raw, signedSep, 2)
	if len(parts) != 2 {
		return ErrInvalidSignature
	}
	payload, sigB64 := parts[0], parts[1]
	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		return ErrInvalidSignature
	}
	payloadBytes := []byte(payload)
	expected := m.signWith(m.primary, payloadBytes)
	if hmac.Equal(sig, expected) {
		return m.decodePayload(payload, dst)
	}
	for _, old := range m.older {
		expected := m.signWith(old, payloadBytes)
		if hmac.Equal(sig, expected) {
			return m.decodePayload(payload, dst)
		}
	}
	return ErrInvalidSignature
}

func (m *SignedManager) decodePayload(payload string, dst any) error {
	dec, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ErrInvalidSignature
	}
	if ptr, ok := dst.(*string); ok {
		*ptr = string(dec)
	}
	return nil
}

func (m *SignedManager) signWith(secret []byte, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

// Set writes a cookie with the given name, value, and options.
func (m *SignedManager) Set(w http.ResponseWriter, name string, value string, opts CookieOptions) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: opts.HTTPOnly,
		SameSite: opts.SameSite,
	}
	if opts.Path == "" {
		c.Path = "/"
	}
	http.SetCookie(w, c)
}

// Clear clears the cookie by setting MaxAge=-1.
func (m *SignedManager) Clear(w http.ResponseWriter, name string, opts CookieOptions) {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   -1,
		Secure:   opts.Secure,
		HttpOnly: opts.HTTPOnly,
		SameSite: opts.SameSite,
	}
	if opts.Path == "" {
		c.Path = "/"
	}
	http.SetCookie(w, c)
}
