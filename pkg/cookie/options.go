package cookie

import "net/http"

// CookieOptions controls how cookies are written and cleared.
type CookieOptions struct {
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
	MaxAge   int
}
