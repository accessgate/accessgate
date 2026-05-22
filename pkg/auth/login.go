package auth

// LoginStartRequest holds input for starting the login flow.
type LoginStartRequest struct {
	// RedirectTo is the URL or path to redirect to after successful login (validated).
	RedirectTo string
	// Prompt forwards supported OIDC prompt values such as "login".
	Prompt string
}

// LoginStartResponse holds the redirect URL for login start.
type LoginStartResponse struct {
	// RedirectURL is the IdP authorization URL (302 redirect).
	RedirectURL string
}

// LoginEndRequest holds callback params for login end.
type LoginEndRequest struct {
	// Code and State from IdP callback query (or error params).
	Code  string
	State string
	// Error from IdP (e.g. access_denied).
	Error            string
	ErrorDescription string
	// Host is the request Host (for optional post-login webhook).
	Host string
}

// LoginEndResponse holds session cookies and redirect target after login.
type LoginEndResponse struct {
	// RedirectURL is where to send the user (app URL or error path).
	RedirectURL string
	// SetCookie is the session cookie value to set (Name+Value+Options applied by HTTP layer).
	SetCookieValue string
	// ClearCookie is true to clear the session cookie (e.g. on error).
	ClearCookie bool
}
