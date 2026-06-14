package auth

// SessionRequest holds input for the session endpoint.
type SessionRequest struct {
	// SessionCookie is the raw session cookie value from the request.
	SessionCookie string
	// Connector selects the identity connector (empty = default connector).
	Connector string
}

// SessionResponse holds the session endpoint response (JSON: is_authenticated, user).
type SessionResponse struct {
	IsAuthenticated bool         `json:"is_authenticated"`
	User            *SessionUser `json:"user,omitempty"`
	// SetCookie is set when the session was refreshed and a new cookie should be sent.
	SetCookie string
}

// SessionUser is the user object returned in /session and /me (from session claims).
type SessionUser struct {
	Sub               string         `json:"sub"`
	Email             string         `json:"email,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Name              string         `json:"name,omitempty"`
	Roles             []string       `json:"roles,omitempty"`
	Groups            []string       `json:"groups,omitempty"`
	IsAdmin           bool           `json:"is_admin,omitempty"`
	TenantContext     map[string]any `json:"tenant_context,omitempty"`
	Claims            map[string]any `json:"claims,omitempty"`
}
