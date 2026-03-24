package proxy

import (
	"context"
	"time"

	"github.com/ArmanAvanesyan/accessgate/internal/authz"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

// AuthPrincipalResolver implements authz.PrincipalResolver by calling accessgate-auth resolve.
type AuthPrincipalResolver struct {
	Client     *AuthClient
	CookieName string
}

// Resolve implements authz.PrincipalResolver.
func (r *AuthPrincipalResolver) Resolve(ctx context.Context, req *authz.Request) (*token.Principal, error) {
	cookieVal := req.Cookies[r.CookieName]
	resp, err := r.Client.Resolve(ctx, cookieVal)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return resolveResponseToPrincipal(resp), nil
}

func resolveResponseToPrincipal(r *ResolveResponse) *token.Principal {
	if r == nil {
		return nil
	}
	claims := token.NormalizeClaims(r.Claims)
	if claims == nil {
		claims = r.Claims
	}
	if claims == nil {
		claims = make(map[string]any)
	}
	sub, _ := claims["sub"].(string)
	var roles []string
	if r, ok := claims["roles"].([]string); ok {
		roles = r
	} else if arr, ok := claims["roles"].([]interface{}); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	var exp time.Time
	if v, ok := claims["exp"]; ok {
		switch t := v.(type) {
		case float64:
			exp = time.Unix(int64(t), 0)
		case int64:
			exp = time.Unix(t, 0)
		}
	}
	p := &token.Principal{
		Subject:       sub,
		Roles:         roles,
		Claims:        claims,
		ExpiresAt:     exp,
		AccessToken:   r.AccessToken,
		TenantContext: r.TenantContext,
	}
	return p
}
