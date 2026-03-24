package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Revoke revokes the given token (refresh or access) at the revocation endpoint if configured.
func (c *Client) Revoke(ctx context.Context, token string) error {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return err
	}
	if disc.RevocationEndpoint == "" {
		return nil
	}
	body := url.Values{
		"token":           {token},
		"token_type_hint": {"refresh_token"},
		"client_id":       {c.clientID},
	}
	if c.clientSecret != "" {
		body.Set("client_secret", c.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.RevocationEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 204 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke: status %d: %s", resp.StatusCode, string(data))
	}
	return nil
}
