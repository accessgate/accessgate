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
	//
	// Reject protocol-relative / backslash-prefixed forms ("//host", "/\host")
	// up front: browsers interpret a leading "//" or "/\" as an absolute URL to
	// another host, so treating them as local paths would be an open redirect
	// (CWE-601). A leading-slash check alone is insufficient — the second
	// character must not be '/' or '\'.
	if strings.HasPrefix(redirectTo, "/") {
		if len(redirectTo) > 1 && (redirectTo[1] == '/' || redirectTo[1] == '\\') {
			return ""
		}
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
	allowed := sameOrigin(origin, baseURL)
	if !allowed {
		for _, o := range allowedOrigins {
			if o == origin {
				allowed = true
				break
			}
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

func sameOrigin(origin string, baseURL string) bool {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base == nil || base.Scheme == "" || base.Host == "" {
		return false
	}
	return origin == base.Scheme+"://"+base.Host
}
