package token

import "context"

// Validator validates JWTs and introspects opaque tokens.
type Validator interface {
	ValidateJWT(ctx context.Context, raw string) (*Principal, error)
	IntrospectOpaque(ctx context.Context, raw string) (*Principal, error)
}
