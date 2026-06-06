package proxy

import (
	"net/http"
	"strings"

	"github.com/accessgate/accessgate/internal/proxy/config"
)

// BuildUpstreamHeaders builds headers for the BFF from session resolve response and config.
func BuildUpstreamHeaders(cfg *config.Config, accessToken string, claims, tenantContext map[string]any) map[string]string {
	h := make(map[string]string)
	if accessToken != "" {
		h["Authorization"] = "Bearer " + accessToken
	}
	if claims == nil {
		return h
	}
	if v := getClaim(claims, cfg.HeaderUserIDClaim); v != "" {
		h["X-User-Id"] = v
	}
	if v := getClaim(claims, cfg.HeaderEmailClaim); v != "" {
		h["X-User-Email"] = v
	}
	if v := getClaim(claims, cfg.HeaderNameClaim); v != "" {
		h["X-User-Full-Name"] = v
	}
	if v := getClaim(claims, cfg.HeaderPreferredUsernameClaim); v != "" {
		h["X-User-Preferred-Username"] = v
	}
	if roles := getClaimSlice(claims, cfg.HeaderRolesClaim); len(roles) > 0 {
		h["X-Roles"] = strings.Join(roles, ",")
	}
	if groups := getClaimSlice(claims, cfg.HeaderGroupsClaim); len(groups) > 0 {
		h["X-Groups"] = strings.Join(groups, ",")
	}
	isAdmin := false
	if cfg.HeaderAdminRole != "" {
		for _, r := range getClaimSlice(claims, cfg.HeaderRolesClaim) {
			if r == cfg.HeaderAdminRole || r == "administrator" {
				isAdmin = true
				break
			}
		}
	}
	if isAdmin {
		h["X-Is-Admin"] = "true"
	} else {
		h["X-Is-Admin"] = "false"
	}
	if tenantContext != nil {
		if v, _ := tenantContext["tenant_id"].(string); v != "" {
			h["X-Tenant-Id"] = v
		}
	}
	if cfg.HeaderTenantIDClaim != "" && claims != nil {
		if v := getClaim(claims, cfg.HeaderTenantIDClaim); v != "" {
			h["X-Tenant-Id"] = v
		}
	}
	return h
}

func getClaim(claims map[string]any, path string) string {
	if path == "" || claims == nil {
		return ""
	}
	parts := strings.Split(path, ".")
	m := claims
	for i, p := range parts {
		v, ok := m[p]
		if !ok {
			return ""
		}
		if i == len(parts)-1 {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}
		m, ok = v.(map[string]any)
		if !ok {
			return ""
		}
	}
	return ""
}

func getClaimSlice(claims map[string]any, path string) []string {
	if path == "" || claims == nil {
		return nil
	}
	parts := strings.Split(path, ".")
	m := claims
	for i, p := range parts {
		v, ok := m[p]
		if !ok {
			return nil
		}
		if i == len(parts)-1 {
			switch x := v.(type) {
			case []interface{}:
				var out []string
				for _, e := range x {
					if s, ok := e.(string); ok {
						out = append(out, s)
					}
				}
				return out
			case []string:
				return x
			}
			return nil
		}
		m, ok = v.(map[string]any)
		if !ok {
			return nil
		}
	}
	return nil
}

// CopyHeaders copies headers from the map into the request.
func CopyHeaders(req *http.Request, h map[string]string) {
	for k, v := range h {
		req.Header.Set(k, v)
	}
}
