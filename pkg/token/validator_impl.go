package token

import (
	"context"
	"errors"
)

var ErrIntrospectNotSupported = errors.New("token: opaque introspection not supported")

// JWTValidator implements Validator for JWT ID tokens (and optionally access tokens) using JWKSSource.
type JWTValidator struct {
	JWKSSource JWKSSource
	Issuer     string
	Audience   string
}

// NewJWTValidator returns a Validator that validates JWTs with the given issuer and optional audience.
func NewJWTValidator(jwks JWKSSource, issuer, audience string) *JWTValidator {
	return &JWTValidator{JWKSSource: jwks, Issuer: issuer, Audience: audience}
}

// ValidateJWT verifies the JWT and returns a Principal. It uses ValidateIDToken with empty nonce.
func (v *JWTValidator) ValidateJWT(ctx context.Context, raw string) (*Principal, error) {
	return ValidateIDToken(ctx, raw, v.JWKSSource, v.Issuer, v.Audience, "")
}

// IntrospectOpaque is not implemented; returns (nil, err) for opaque tokens.
func (v *JWTValidator) IntrospectOpaque(ctx context.Context, raw string) (*Principal, error) {
	return nil, ErrIntrospectNotSupported
}
