package token

import "time"

// Principal is the normalized identity model extracted from tokens.
type Principal struct {
	Subject       string
	Scopes        []string
	Roles         []string
	Claims        map[string]any
	ExpiresAt     time.Time
	AccessToken   string         // Optional; for upstream Authorization header when set.
	TenantContext map[string]any // Optional; for upstream X-Tenant-* headers when set.
}

// NormalizeClaims returns a copy of claims with standard paths normalized for use with Principal.
// Standard paths: sub, exp, iss, aud, nonce; roles from realm_access.roles or roles; groups if present.
// Roles are normalized to a consistent []string shape when present.
func NormalizeClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	out := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		out[k] = v
	}
	// Normalize roles: ensure "roles" key exists as []string when realm_access.roles or roles present
	var roles []string
	if r, ok := claims["realm_access"].(map[string]any); ok {
		if arr, ok := r["roles"].([]interface{}); ok {
			for _, x := range arr {
				if s, ok := x.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	if len(roles) == 0 {
		if r, ok := claims["roles"].([]interface{}); ok {
			for _, x := range r {
				if s, ok := x.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	if len(roles) > 0 {
		out["roles"] = roles
	}
	return out
}
