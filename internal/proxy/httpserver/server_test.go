package httpserver

import (
	"testing"

	"github.com/ArmanAvanesyan/accessgate/internal/policy"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy/config"
)

func TestNewReturnsServerWithHandler(t *testing.T) {
	cfg := &config.Config{
		UpstreamURL:     "http://localhost:8002",
		ProxyPathPrefix: "/graphql",
		AuthURL:         "http://localhost:8080",
		CookieName:      "test",
	}
	client := proxy.NewAuthClient(cfg.AuthURL, cfg.CookieName)
	s := New(cfg, client, policy.NewWASMRuntime(policy.DefaultFallbackAllow), nil, nil, nil, nil, nil)
	if s == nil {
		t.Fatalf("expected non-nil Server")
	}
	if s.Handler() == nil {
		t.Fatalf("expected non-nil Handler")
	}
}
