package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TokenResponse is the OAuth token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// Exchange exchanges the authorization code for tokens.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"code_verifier": {codeVerifier},
	}
	if c.clientSecret != "" {
		body.Set("client_secret", c.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange: status %d: %s", resp.StatusCode, string(data))
	}
	var tr TokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// Refresh refreshes tokens using the refresh_token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	body := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
	}
	if c.clientSecret != "" {
		body.Set("client_secret", c.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh: status %d: %s", resp.StatusCode, string(data))
	}
	var tr TokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}
