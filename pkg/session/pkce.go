package session

// PKCEState holds the PKCE and redirect state stored keyed by state.
type PKCEState struct {
	State         string `json:"state"`
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	Nonce         string `json:"nonce"`
	RedirectTo    string `json:"redirect_to"` // validated redirect URL/path after login
}
