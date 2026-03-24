package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkgproxy "github.com/ArmanAvanesyan/accessgate/internal/authz"
	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/ArmanAvanesyan/accessgate/internal/plugins/register"
	"github.com/ArmanAvanesyan/accessgate/internal/policy"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy/config"
	"github.com/ArmanAvanesyan/accessgate/internal/proxy/httpserver"
	"github.com/ArmanAvanesyan/accessgate/pkg/observability"
)

func main() {
	logger := log.New(os.Stdout, "[accessgate-proxy] ", log.LstdFlags|log.LUTC)
	logger.Println("starting accessgate-proxy")

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("config load: %v", err)
	}
	client := proxy.NewAuthClient(cfg.AuthURL, cfg.CookieName)

	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(context.Background(), reg); err != nil {
		logger.Fatalf("register built-in plugins: %v", err)
	}
	if cfg.PluginsManifestDir != "" {
		ctx := context.Background()
		if err := plugin.DiscoverFromDir(ctx, reg, cfg.PluginsManifestDir, nil); err != nil {
			logger.Printf("plugin discovery: %v (continuing without manifest plugins)", err)
		} else if err := reg.BuildDependencyGraph(); err != nil {
			logger.Printf("plugin dependency graph: %v (continuing)", err)
		}
	}

	metrics, metricsHandler := observability.NewPrometheusMetrics(nil)
	tracer, tracerShutdown := observability.NewOTLPTracerFromEnvWithShutdown()
	policyEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		logger.Fatalf("policy engine: %v", err)
	}
	pipelinePlugins, err := buildPipelinePlugins(cfg, reg)
	if err != nil {
		logger.Fatalf("pipeline plugins: %v", err)
	}
	handler := httpserver.New(cfg, client, policyEngine, pipelinePlugins, reg, metrics, metricsHandler, tracer).Handler()

	srv := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: handler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server error: %v", err)
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-sigCtx.Done()
	logger.Println("shutting down accessgate-proxy")

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
		configPath = os.Getenv("PROXY_CONFIG")
	}
	return config.Load(context.Background(), configPath)
}

func buildPolicyEngine(cfg *config.Config) (policy.Engine, error) {
	fallback := policy.FallbackConfig{Allow: cfg.PolicyFallbackAllow != nil && *cfg.PolicyFallbackAllow}

	switch cfg.PolicyEngine {
	case config.PolicyEngineWASM:
		if cfg.PolicyBundlePath == "" {
			return policy.NewWASMRuntime(fallback), nil
		}
		loader := policy.NewBundleLoader(fallback, cfg.BundlePublicKeyPath)
		return loader.LoadBundle(cfg.PolicyBundlePath)
	case config.PolicyEngineRego:
		eng := policy.NewRegoEngine(fallback)
		if cfg.PolicyBundlePath != "" {
			if err := eng.Load(cfg.PolicyBundlePath); err != nil {
				return nil, err
			}
		}
		return eng, nil
	default:
		// Should not happen due to ApplyDefaults+Validate, but keep a safe fallback.
		return policy.NewWASMRuntime(fallback), nil
	}
}

func buildPipelinePlugins(cfg *config.Config, reg *plugin.Registry) ([]pkgproxy.PipelinePlugin, error) {
	if reg == nil || len(cfg.PipelinePlugins) == 0 {
		return nil, nil
	}

	ctx := context.Background()
	out := make([]pkgproxy.PipelinePlugin, 0, len(cfg.PipelinePlugins))

	for _, entry := range cfg.PipelinePlugins {
		if entry.ID == "" {
			continue
		}
		regEntry, ok := reg.RegistrationFor(plugin.PluginID(entry.ID))
		if !ok || regEntry == nil {
			return nil, fmt.Errorf("pipeline plugin %q not registered", entry.ID)
		}

		p, err := regEntry.Factory(ctx, regEntry.Descriptor)
		if err != nil {
			return nil, fmt.Errorf("pipeline plugin %q factory: %w", entry.ID, err)
		}
		if p == nil {
			return nil, fmt.Errorf("pipeline plugin %q factory returned nil", entry.ID)
		}

		if cp, ok := p.(plugin.ConfigurablePlugin); ok {
			if err := cp.Configure(ctx, entry.Raw); err != nil {
				return nil, fmt.Errorf("pipeline plugin %q configure: %w", entry.ID, err)
			}
		}
		if sp, ok := p.(plugin.StartablePlugin); ok {
			if err := sp.Start(ctx); err != nil {
				return nil, fmt.Errorf("pipeline plugin %q start: %w", entry.ID, err)
			}
		}

		pl, ok := p.(plugin.PipelinePlugin)
		if !ok {
			return nil, fmt.Errorf("pipeline plugin %q is not a PipelinePlugin", entry.ID)
		}

		out = append(out, pl)
	}

	return out, nil
}
