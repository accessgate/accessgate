package service

import (
	"net/url"
	"strings"
)

// ValidateRedirect checks redirectTo against allowed origins and path prefixes.
// redirectTo can be a full URL or a path. Returns the URL to redirect to (absolute) or empty if invalid.
func ValidateRedirect(redirectTo string, baseURL string, allowedOrigins, allowedPathPrefixes []string) string {
	redirectTo = strings.TrimSpace(redirectTo)
	if redirectTo == "" {
		return baseURL
	}
	// If it's a path (starts with /), validate and make it absolute using baseURL.
	if strings.HasPrefix(redirectTo, "/") {
		pathAllowed := len(allowedPathPrefixes) == 0
		for _, p := range allowedPathPrefixes {
			if p == "/" || strings.HasPrefix(redirectTo, p) {
				pathAllowed = true
				break
			}
		}
		if !pathAllowed {
			return ""
		}
		base := strings.TrimSuffix(baseURL, "/")
		return base + redirectTo
	}
	// Full URL: check origin and optionally path.
	u, err := url.Parse(redirectTo)
	if err != nil {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	origin := u.Scheme + "://" + u.Host
	allowed := false
	for _, o := range allowedOrigins {
		if o == origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return ""
	}
	// Optionally check path prefix against allowedPathPrefixes.
	if len(allowedPathPrefixes) > 0 {
		pathAllowed := false
		for _, p := range allowedPathPrefixes {
			if p == "/" || strings.HasPrefix(u.Path, p) {
				pathAllowed = true
				break
			}
		}
		if !pathAllowed {
			return ""
		}
	}
	return redirectTo
}
