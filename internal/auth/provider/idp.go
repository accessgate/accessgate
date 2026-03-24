package provider

import (
	"context"

	"github.com/ArmanAvanesyan/accessgate/pkg/oidc"
)

// IdP is the identity-provider abstraction used by the agent service for login, callback, refresh, and logout.
// The built-in oidc.Client implements this interface; a provider plugin can be adapted to implement it later.
type IdP interface {
	AuthURL(ctx context.Context, state, codeChallenge, nonce string) (string, error)
	Exchange(ctx context.Context, code, codeVerifier string) (*oidc.TokenResponse, error)
	Refresh(ctx context.Context, refreshToken string) (*oidc.TokenResponse, error)
	EndSessionURL(ctx context.Context, idTokenHint, postLogoutRedirectURI string) (string, error)
}

// Ensure *oidc.Client implements IdP.
var _ IdP = (*oidc.Client)(nil)
