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
	claims := normalizeClaims(r.Claims)
	if claims == nil {
		claims = make(map[string]any)
	}
	sub, _ := claims["sub"].(string)
	roles := extractRoles(claims)
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

func normalizeClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	out := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		out[k] = v
	}
	if roles := extractRoles(claims); len(roles) > 0 {
		out["roles"] = roles
	}
	return out
}

func extractRoles(claims map[string]any) []string {
	if claims == nil {
		return nil
	}
	if realmAccess, ok := claims["realm_access"].(map[string]any); ok {
		if roles := stringsFromAnySlice(realmAccess["roles"]); len(roles) > 0 {
			return roles
		}
	}
	if roles, ok := claims["roles"].([]string); ok {
		return append([]string(nil), roles...)
	}
	return stringsFromAnySlice(claims["roles"])
}

func stringsFromAnySlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []interface{}:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
