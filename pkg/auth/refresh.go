package auth

// RefreshRequest holds session cookie for refresh.
type RefreshRequest struct {
	SessionCookie string
	// Connector selects the identity connector (empty = default connector).
	Connector string
}

// RefreshResponse holds updated cookie after refresh (or 401 when invalid/expired).
type RefreshResponse struct {
	// SetCookieValue is the new session cookie value when tokens were refreshed.
	SetCookieValue string
	// Refreshed is true when a new cookie was issued.
	Refreshed bool
}
