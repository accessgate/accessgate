package oidcprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/pkg/oidc"
)

// Config matches schemas/plugins/provider/oidc.schema.json.
type Config struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Scopes       Scopes `json:"scopes"`
	ClaimsSource string `json:"claims_source"`
	Audience     string `json:"audience"`
}

// Scopes supports both JSON string and JSON array forms.
type Scopes []string

func (s *Scopes) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		parts := strings.FieldsFunc(str, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' })
		*s = parts
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*s = arr
	return nil
}

type Plugin struct {
	mu   sync.RWMutex
	cfg  Config
	oidc *oidc.Client
}

var _ plugin.ProviderPlugin = (*Plugin)(nil)
var _ plugin.ConfigurablePlugin = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Descriptor() plugin.PluginDescriptor {
	return plugin.PluginDescriptor{
		ID:              plugin.PluginID("provider:oidc"),
		Kind:            plugin.PluginKindProvider,
		Name:            "OIDC Provider",
		Description:     "OIDC provider plugin (authorization code + PKCE)",
		Version:         "v1",
		Capabilities:    []plugin.Capability{"provider:oidc"},
		ConfigSchemaRef: "plugins/provider/oidc",
		VersionInfo: plugin.VersionInfo{
			APIVersion:        "",
			MinRuntimeVersion: "",
			MaxRuntimeVersion: "",
		},
	}
}

func (p *Plugin) Configure(ctx context.Context, cfg any) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("oidc provider: marshal config: %w", err)
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("oidc provider: decode config: %w", err)
	}
	if out.Issuer == "" || out.ClientID == "" || out.RedirectURI == "" {
		return fmt.Errorf("oidc provider: issuer, client_id, redirect_uri are required")
	}
	if len(out.Scopes) == 0 {
		out.Scopes = []string{"openid", "profile"}
	}

	cl := oidc.NewClient(out.Issuer, out.ClientID, out.ClientSecret, out.RedirectURI, []string(out.Scopes), out.Audience)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = out
	p.oidc = cl
	return nil
}

func (p *Plugin) Health(ctx context.Context) plugin.PluginHealth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.oidc == nil {
		return plugin.PluginHealth{State: plugin.PluginStateDegraded, Message: "not configured"}
	}
	return plugin.PluginHealth{
		State:   plugin.PluginStateHealthy,
		Message: "configured",
		Details: map[string]any{"issuer": p.cfg.Issuer},
	}
}

func (p *Plugin) AuthorizationURL(ctx context.Context, state string, codeChallenge string, nonce string, extraParams map[string]string) (string, error) {
	p.mu.RLock()
	oidcClient := p.oidc
	p.mu.RUnlock()
	if oidcClient == nil {
		return "", fmt.Errorf("oidc provider: not configured")
	}
	authURL, err := oidcClient.AuthURL(ctx, state, codeChallenge, nonce)
	if err != nil {
		return "", err
	}
	if len(extraParams) == 0 {
		return authURL, nil
	}
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for key, value := range extraParams {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *Plugin) ExchangeCode(ctx context.Context, code string, codeVerifier string, redirectURI string) (*plugin.ProviderTokens, error) {
	p.mu.RLock()
	oidcClient := p.oidc
	p.mu.RUnlock()
	if oidcClient == nil {
		return nil, fmt.Errorf("oidc provider: not configured")
	}
	_ = redirectURI // oidc client is already constructed with redirectURI

	tr, err := oidcClient.Exchange(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}
	return &plugin.ProviderTokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresIn:    tr.ExpiresIn,
	}, nil
}

func (p *Plugin) Refresh(ctx context.Context, refreshToken string) (*plugin.ProviderTokens, error) {
	p.mu.RLock()
	oidcClient := p.oidc
	p.mu.RUnlock()
	if oidcClient == nil {
		return nil, fmt.Errorf("oidc provider: not configured")
	}
	tr, err := oidcClient.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return &plugin.ProviderTokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresIn:    tr.ExpiresIn,
	}, nil
}

func (p *Plugin) EndSessionURL(ctx context.Context, idTokenHint, postLogoutRedirectURI string) (string, error) {
	p.mu.RLock()
	oidcClient := p.oidc
	p.mu.RUnlock()
	if oidcClient == nil {
		return "", fmt.Errorf("oidc provider: not configured")
	}
	return oidcClient.EndSessionURL(ctx, idTokenHint, postLogoutRedirectURI)
}
