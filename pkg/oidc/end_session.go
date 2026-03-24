package oidc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// EndSessionURL returns the URL to redirect the user to for logout (end_session_endpoint).
// postLogoutRedirectURI is validated: scheme must be https or http and must not be empty.
func (c *Client) EndSessionURL(ctx context.Context, idTokenHint, postLogoutRedirectURI string) (string, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return "", err
	}
	if disc.EndSessionEndpoint == "" {
		return "", nil
	}
	params := url.Values{}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		if err := validateLogoutRedirectURI(postLogoutRedirectURI); err != nil {
			return "", fmt.Errorf("end_session: %w", err)
		}
		params.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	q := params.Encode()
	if q != "" {
		return strings.TrimSuffix(disc.EndSessionEndpoint, "/") + "?" + q, nil
	}
	return disc.EndSessionEndpoint, nil
}

// validateLogoutRedirectURI checks that the URI has an http or https scheme and a non-empty host.
func validateLogoutRedirectURI(rawURI string) error {
	u, err := url.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("invalid post_logout_redirect_uri: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("post_logout_redirect_uri scheme %q not allowed (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("post_logout_redirect_uri has no host")
	}
	return nil
}
