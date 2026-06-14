package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/accessgate/accessgate/internal/auth/config"
	"github.com/accessgate/accessgate/internal/auth/httpserver"
	"github.com/accessgate/accessgate/internal/auth/service"
	"github.com/accessgate/accessgate/internal/healthcheck"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/plugins/register"
	"github.com/accessgate/accessgate/internal/redis"
	"github.com/accessgate/accessgate/pkg/cookie"
	"github.com/accessgate/accessgate/pkg/observability"
	"github.com/accessgate/accessgate/pkg/token"
)

func main() {
	// "healthcheck" subcommand: used as the in-container Docker HEALTHCHECK on
	// the shell-less distroless image. It performs a single GET to /healthz and
	// exits 0/1. Must run before any config load so it stays self-contained.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck.Run("HTTP_PORT", "8080", "/healthz"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	logger := log.New(os.Stdout, "[accessgate-auth] ", log.LstdFlags|log.LUTC)
	logger.Println("starting accessgate-auth")

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("config load: %v", err)
	}

	ctx := context.Background()

	metrics, metricsHandler := observability.NewPrometheusMetrics(nil)
	tracer, tracerShutdown := observability.NewOTLPTracerFromEnvWithShutdown()

	cookieManager := cookie.NewSignedManager(cfg.CookieSigningSecret)
	jwks := token.NewHTTPJWKSSource(5*time.Minute, metrics)

	// Build one connector per configured connector, each with its own provider instance and
	// Redis-namespaced stores (same Redis server, distinct key prefix). The default connector's
	// store seam is reused for readiness checks and admin lookups.
	connectors := make([]service.Connector, 0, len(cfg.Connectors))
	var defaultStore *redis.Store
	for i := range cfg.Connectors {
		cc := cfg.Connectors[i]
		store, err := redis.New(ctx, cfg.RedisURL, cc.KeyLayout(), metrics)
		if err != nil {
			logger.Fatalf("redis (connector %s): %v", cc.ID, err)
		}
		defer func(s *redis.Store, id string) {
			if err := s.Close(); err != nil {
				logger.Printf("redis close (connector %s): %v", id, err)
			}
		}(store, cc.ID)
		provider, err := buildProviderPlugin(cc)
		if err != nil {
			logger.Fatalf("provider plugin (connector %s): %v", cc.ID, err)
		}
		connectors = append(connectors, service.Connector{
			Config:      cc,
			Provider:    provider,
			Sessions:    store.SessionStore(),
			PKCE:        store.PKCEStore(),
			RefreshLock: store.RefreshLockStore(),
			Finder:      store, // *redis.Store implements FindSessionBySubjectEmail (handoff issue)
		})
		if bool(cc.Default) || defaultStore == nil {
			defaultStore = store
		}
	}

	svc, err := service.NewMultiConnector(
		cfg,
		connectors,
		cookieManager,
		jwks,
		tracer,
		metrics,
	)
	if err != nil {
		logger.Fatalf("service: %v", err)
	}
	// Enable signed one-time handoff tickets, using the default connector's Redis store for
	// replay protection (atomic SETNX consume).
	svc.EnableHandoff(defaultStore, 0)

	srv := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: httpserver.New(svc, cfg, defaultStore, metricsHandler).Handler(),
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		logger.Printf("http server error: %v", err)
		os.Exit(1)
	case <-sigCtx.Done():
	}
	logger.Println("shutting down accessgate-auth")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if tracerShutdown != nil {
		tracerCtx, tracerCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tracerCancel()
		if err := tracerShutdown(tracerCtx); err != nil {
			logger.Printf("tracer shutdown: %v", err)
		}
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}

func loadConfig() (*config.Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = os.Getenv("AUTH_CONFIG")
	}
	if configPath == "" {
		configPath = os.Getenv("AGENT_CONFIG")
	}
	return config.Load(context.Background(), configPath)
}

// buildProviderPlugin constructs and configures a fresh provider plugin instance for one
// connector. A new instance per connector is required because oidcprovider.Plugin holds a
// single configured OIDC client.
func buildProviderPlugin(cc config.ConnectorConfig) (plugin.ProviderPlugin, error) {
	ctx := context.Background()
	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(ctx, reg); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(cc.ProviderPluginID)
	if id == "" {
		id = "provider:oidc"
	} else if !strings.Contains(id, ":") {
		id = "provider:" + id
	}

	regEntry, ok := reg.RegistrationFor(plugin.PluginID(id))
	if !ok || regEntry == nil {
		return nil, fmt.Errorf("provider plugin %q not registered", id)
	}

	p, err := regEntry.Factory(ctx, regEntry.Descriptor)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("provider plugin %q factory returned nil", id)
	}

	provider, ok := p.(plugin.ProviderPlugin)
	if !ok {
		return nil, fmt.Errorf("provider plugin %q does not implement ProviderPlugin", id)
	}

	if cp, ok := p.(plugin.ConfigurablePlugin); ok {
		providerCfg := map[string]any{
			"issuer":        cc.OIDCIssuer,
			"client_id":     cc.OIDCClientID,
			"client_secret": cc.OIDCClientSecret,
			"redirect_uri":  cc.OIDCRedirectURI,
			"scopes":        []string(cc.OIDCScopes),
			"claims_source": cc.OIDCClaimsSource,
			"audience":      cc.OIDCAudience,
		}
		if err := cp.Configure(ctx, providerCfg); err != nil {
			return nil, err
		}
	}

	return provider, nil
}
