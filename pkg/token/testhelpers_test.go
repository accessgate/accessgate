package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKID is the key id used by the default in-test signing key.
const testKID = "test-kid"

// rsaTestKey generates a deterministic-enough RSA key for tests.
// A fresh 2048-bit key is created per call (large enough to pass the
// 2048-bit minimum enforced in keyFuncFromJWKS).
func rsaTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func ecTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

// rsaJWKS builds a single-key RSA JWKS document for the given key/kid.
func rsaJWKS(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   n,
				"e":   e,
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// ecJWKS builds a single-key EC (P-256) JWKS document for the given key/kid.
func ecJWKS(t *testing.T, key *ecdsa.PrivateKey, kid string) []byte {
	t.Helper()
	const fieldBytes = 32 // P-256
	x := make([]byte, fieldBytes)
	y := make([]byte, fieldBytes)
	xb := key.X.Bytes()
	yb := key.Y.Bytes()
	copy(x[fieldBytes-len(xb):], xb)
	copy(y[fieldBytes-len(yb):], yb)
	doc := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"use": "sig",
				"alg": "ES256",
				"kid": kid,
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(x),
				"y":   base64.RawURLEncoding.EncodeToString(y),
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal ec jwks: %v", err)
	}
	return b
}

// signRS256 mints an RS256-signed JWT with the given claims and kid header.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return s
}

// signES256 mints an ES256-signed JWT with the given claims and kid header.
func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign ES256: %v", err)
	}
	return s
}

// validClaims returns a baseline set of valid ID-token claims for issuer/audience.
func validClaims(issuer, audience string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// staticJWKSSource is a JWKSSource backed by fixed bytes (or an error).
// It records the number of GetJWKS invocations.
type staticJWKSSource struct {
	data  []byte
	err   error
	calls int
}

func (s *staticJWKSSource) GetJWKS(_ context.Context, _ string) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.data, nil
}
