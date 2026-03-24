package token

import "context"

// JWKSSource provides raw JWKS for JWT verification.
type JWKSSource interface {
	GetJWKS(ctx context.Context, issuer string) ([]byte, error)
}
