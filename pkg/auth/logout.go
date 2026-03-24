package auth

// LogoutRequest holds session and redirect target for logout.
type LogoutRequest struct {
	SessionCookie string
	// RedirectTo is the post-logout redirect URI (validated).
	RedirectTo string
	// Origin/Referer for CSRF check on POST.
	Origin  string
	Referer string
}

// LogoutResponse holds redirect to IdP end_session (and HTTP layer clears cookie).
type LogoutResponse struct {
	// RedirectURL is the IdP end_session_endpoint URL with id_token_hint and post_logout_redirect_uri.
	RedirectURL string
	// ClearCookie is true so the HTTP layer clears the session cookie.
	ClearCookie bool
}
