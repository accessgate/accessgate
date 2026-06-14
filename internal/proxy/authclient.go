package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ResolveResponse is the response from accessgate-auth GET /internal/resolve.
type ResolveResponse struct {
	AccessToken   string         `json:"access_token"`
	Claims        map[string]any `json:"claims"`
	TenantContext map[string]any `json:"tenant_context"`
}

// AuthClient calls accessgate-auth for session resolution.
type AuthClient struct {
	baseURL    string
	cookieName string
	httpClient *http.Client
}

// NewAuthClient creates a client for accessgate-auth at baseURL (e.g. http://accessgate-auth:8080).
func NewAuthClient(baseURL, cookieName string) *AuthClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &AuthClient{
		baseURL:    baseURL,
		cookieName: cookieName,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Resolve calls GET /internal/resolve with the session cookie (default connector).
func (c *AuthClient) Resolve(ctx context.Context, sessionCookie string) (*ResolveResponse, error) {
	return c.ResolveConnector(ctx, sessionCookie, "")
}

// ResolveConnector calls GET /internal/resolve?connector=<id> with the session cookie and
// returns session data. An empty connectorID resolves against the default connector.
func (c *AuthClient) ResolveConnector(ctx context.Context, sessionCookie, connectorID string) (*ResolveResponse, error) {
	reqURL := c.baseURL + "/internal/resolve"
	if connectorID != "" {
		reqURL += "?connector=" + url.QueryEscape(connectorID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if sessionCookie != "" {
		req.Header.Set("Cookie", c.cookieName+"="+sessionCookie)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth resolve: status %d: %s", resp.StatusCode, string(body))
	}
	var out ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetCookieFromResponse copies Set-Cookie headers from the auth response to the proxy response.
func SetCookieFromResponse(dst, src http.Header) {
	for _, v := range src["Set-Cookie"] {
		dst.Add("Set-Cookie", v)
	}
}
