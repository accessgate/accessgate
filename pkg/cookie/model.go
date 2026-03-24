package cookie

import "net/http"

// OutCookie represents a cookie the proxy wishes to set on the response.
type OutCookie struct {
	Name    string
	Value   string
	Options CookieOptions
}

// SessionCookieConfig describes the policy for the primary browser session cookie.
type SessionCookieConfig struct {
	Name     string
	Domain   string
	Path     string
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
}

// Options returns CookieOptions derived from the config.
func (c SessionCookieConfig) Options() CookieOptions {
	opts := CookieOptions{
		Path:     c.Path,
		Domain:   c.Domain,
		Secure:   c.Secure,
		HTTPOnly: c.HTTPOnly,
		SameSite: c.SameSite,
		MaxAge:   c.MaxAge,
	}
	if opts.Path == "" {
		opts.Path = "/"
	}
	return opts
}

// DefaultSessionCookieConfig returns safe defaults for the browser session cookie.
func DefaultSessionCookieConfig(name string) SessionCookieConfig {
	return SessionCookieConfig{
		Name:     name,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// WriteOutCookie writes the cookie to the response writer.
func WriteOutCookie(w http.ResponseWriter, c OutCookie) {
	hc := &http.Cookie{
		Name:     c.Name,
		Value:    c.Value,
		Path:     c.Options.Path,
		Domain:   c.Options.Domain,
		MaxAge:   c.Options.MaxAge,
		Secure:   c.Options.Secure,
		HttpOnly: c.Options.HTTPOnly,
		SameSite: c.Options.SameSite,
	}
	if hc.Path == "" {
		hc.Path = "/"
	}
	http.SetCookie(w, hc)
}
