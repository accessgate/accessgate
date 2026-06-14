package authz

import "github.com/accessgate/accessgate/pkg/cookie"

// Response is the result of proxy evaluation and policy enforcement.
type Response struct {
	Allow           bool
	UpstreamHeaders map[string]string
	SetCookies      []cookie.OutCookie
	StatusCode      int
	Body            []byte
	// RedirectTo, when non-empty on a denied response, instructs the HTTP layer to issue a
	// 302 redirect (browser/html_redirect mode) instead of writing the status/body.
	RedirectTo string
}
