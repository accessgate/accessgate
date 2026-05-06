package httpserver

import (
	"testing"

	pkgproxy "github.com/ArmanAvanesyan/accessgate/internal/authz"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy/config"
)

func TestNewReturnsServerWithHandler(t *testing.T) {
	cfg := &config.Config{
		UpstreamURL:     "http://localhost:8002",
		ProxyPathPrefix: "/graphql",
		AuthURL:         "http://localhost:8080",
		CookieName:      "test",
	}
	engine := &pkgproxy.DefaultEngine{UpstreamURL: cfg.UpstreamURL}
	s := New(cfg, engine, nil, nil)
	if s == nil {
		t.Fatalf("expected non-nil Server")
	}
	if s.Handler() == nil {
		t.Fatalf("expected non-nil Handler")
	}
}
