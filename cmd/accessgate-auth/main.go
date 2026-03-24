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

	"github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	"github.com/ArmanAvanesyan/accessgate/internal/auth/httpserver"
	"github.com/ArmanAvanesyan/accessgate/internal/auth/service"
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/internal/plugins/register"
	"github.com/ArmanAvanesyan/accessgate/internal/redis"
	"github.com/ArmanAvanesyan/accessgate/pkg/cookie"
	"github.com/ArmanAvanesyan/accessgate/pkg/observability"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

func main() {
	logger := log.New(os.Stdout, "[accessgate-auth] ", log.LstdFlags|log.LUTC)
	logger.Println("starting accessgate-auth")

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("config load: %v", err)
	}

	ctx := context.Background()
	layout := cfg.KeyLayout()

	metrics, metricsHandler := observability.NewPrometheusMetrics(nil)
	tracer, tracerShutdown := observability.NewOTLPTracerFromEnvWithShutdown()

	store, err := redis.New(ctx, cfg.RedisURL, layout, metrics)
	if err != nil {
		logger.Fatalf("redis: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Printf("redis close: %v", err)
		}
	}()

	cookieManager := cookie.NewSignedManager(cfg.CookieSigningSecret)
	jwks := token.NewHTTPJWKSSource(5*time.Minute, metrics)

	provider, err := buildProviderPlugin(cfg)
	if err != nil {
		logger.Fatalf("provider plugin: %v", err)
	}

	svc, err := service.New(
		cfg,
		store.SessionStore(),
		store.PKCEStore(),
		store.RefreshLockStore(),
		cookieManager,
		jwks,
		provider,
		tracer,
		metrics,
	)
	if err != nil {
		logger.Fatalf("service: %v", err)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: httpserver.New(svc, cfg, store, metricsHandler).Handler(),
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

func buildProviderPlugin(cfg *config.Config) (plugin.ProviderPlugin, error) {
	ctx := context.Background()
	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(ctx, reg); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(cfg.ProviderPluginID)
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
			"issuer":        cfg.OIDCIssuer,
			"client_id":     cfg.OIDCClientID,
			"client_secret": cfg.OIDCClientSecret,
			"redirect_uri":  cfg.OIDCRedirectURI,
			"scopes":        cfg.OIDCScopesSlice(),
			"claims_source": cfg.OIDCClaimsSource,
			"audience":      cfg.OIDCAudience,
		}
		if err := cp.Configure(ctx, providerCfg); err != nil {
			return nil, err
		}
	}

	return provider, nil
}
