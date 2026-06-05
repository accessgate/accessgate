package token

import (
	"context"
	"errors"
	"testing"
)

func TestNewJWTValidator(t *testing.T) {
	src := &staticJWKSSource{}
	v := NewJWTValidator(src, testIssuer, testAudience)
	if v.JWKSSource != src || v.Issuer != testIssuer || v.Audience != testAudience {
		t.Fatalf("validator fields not set: %+v", v)
	}
	// Ensure it satisfies the Validator interface.
	var _ Validator = v
}

func TestJWTValidator_ValidateJWT(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	v := NewJWTValidator(src, testIssuer, testAudience)
	raw := signRS256(t, key, testKID, validClaims(testIssuer, testAudience))

	p, err := v.ValidateJWT(context.Background(), raw)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if p.Subject != "user-123" {
		t.Fatalf("subject = %q", p.Subject)
	}
}

func TestJWTValidator_ValidateJWT_Invalid(t *testing.T) {
	key := rsaTestKey(t)
	src := &staticJWKSSource{data: rsaJWKS(t, key, testKID)}
	v := NewJWTValidator(src, testIssuer, testAudience)

	if _, err := v.ValidateJWT(context.Background(), "garbage"); err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestJWTValidator_IntrospectOpaque_NotSupported(t *testing.T) {
	v := NewJWTValidator(&staticJWKSSource{}, testIssuer, testAudience)
	p, err := v.IntrospectOpaque(context.Background(), "opaque")
	if p != nil {
		t.Fatalf("expected nil principal, got %+v", p)
	}
	if !errors.Is(err, ErrIntrospectNotSupported) {
		t.Fatalf("expected ErrIntrospectNotSupported, got %v", err)
	}
}
