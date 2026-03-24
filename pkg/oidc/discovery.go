package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Discovery holds OIDC provider metadata from discovery document.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// Client is an OIDC client that uses discovery and performs auth flows.
type Client struct {
	issuer        string
	clientID      string
	clientSecret  string
	redirectURI   string
	scopes        []string
	audience      string
	discovery     *Discovery
	discoveryOnce sync.Once
	discoveryErr  error
	httpClient    *http.Client
}

// NewClient creates an OIDC client. Discovery is fetched on first use.
func NewClient(issuer, clientID, clientSecret, redirectURI string, scopes []string, audience string) *Client {
	if scopes == nil {
		scopes = []string{"openid", "profile"}
	}
	return &Client{
		issuer:       strings.TrimSuffix(issuer, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		scopes:       scopes,
		audience:     audience,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Discovery fetches and caches the OIDC discovery document.
func (c *Client) Discovery(ctx context.Context) (*Discovery, error) {
	c.discoveryOnce.Do(func() {
		c.discovery, c.discoveryErr = c.fetchDiscovery(ctx)
	})
	return c.discovery, c.discoveryErr
}

func (c *Client) fetchDiscovery(ctx context.Context) (*Discovery, error) {
	u := c.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery %s: status %d", u, resp.StatusCode)
	}
	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery: missing required endpoints")
	}
	return &d, nil
}

// AuthURL returns the authorization URL for the authorization code flow with PKCE.
func (c *Client) AuthURL(ctx context.Context, state, codeChallenge, nonce string) (string, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return "", err
	}
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.clientID},
		"redirect_uri":          {c.redirectURI},
		"scope":                 {strings.Join(c.scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
	}
	if c.audience != "" {
		params.Set("audience", c.audience)
	}
	return disc.AuthorizationEndpoint + "?" + params.Encode(), nil
}
