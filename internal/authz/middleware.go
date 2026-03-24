package authz

import (
	"net/http"
)

// Middleware returns an HTTP middleware that delegates to the proxy Engine.
// When the engine allows the request, it proxies to upstreamURL with the response upstream headers.
// When the engine denies, it writes the response status and body (no proxy).
func Middleware(e Engine, upstreamURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, err := RequestFromHTTP(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp, err := e.Handle(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if resp.Allow && upstreamURL != "" {
				_ = ProxyToUpstream(r.Context(), w, r, upstreamURL, resp.UpstreamHeaders, req.Body)
				return
			}
			WriteResponse(w, resp)
		})
	}
}
