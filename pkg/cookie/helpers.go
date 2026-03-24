package cookie

import "net/http"

// ReadSessionID returns the value of the named cookie from the request, or "" if missing.
// Session body is stored in Redis keyed by this ID; see docs/architecture/cookie-model.md.
func ReadSessionID(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}
