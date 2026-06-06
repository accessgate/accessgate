package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	pkgproxy "github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/plugins/register"
	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/internal/proxy"
	"github.com/accessgate/accessgate/internal/proxy/config"
	"github.com/accessgate/accessgate/internal/proxy/httpserver"
	"github.com/accessgate/accessgate/pkg/observability"
)

func loadConfig() (*config.Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = os.Getenv("PROXY_CONFIG")
	}
	return config.Load(context.Background(), configPath)
}

func buildProxyHandler(ctx context.Context, cfg *config.Config) (http.Handler, func(context.Context) error, error) {
	client := proxy.NewAuthClient(cfg.AuthURL, cfg.CookieName)

	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(ctx, reg); err != nil {
		return nil, nil, fmt.Errorf("register built-in plugins: %w", err)
	}
	if cfg.PluginsManifestDir != "" {
		// Keep manifest discovery and dependency graph assembly best-effort,
		// matching the previous bootstrap behavior while avoiding lint-only
		// empty branches.
		if err := plugin.DiscoverFromDir(ctx, reg, cfg.PluginsManifestDir, nil); err == nil {
			_ = reg.BuildDependencyGraph()
		}
	}

	metrics, metricsHandler := observability.NewPrometheusMetrics(nil)
	tracer, tracerShutdown := observability.NewOTLPTracerFromEnvWithShutdown()
	policyEngine, err := buildPolicyEngine(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("policy engine: %w", err)
	}
	pipelinePlugins, err := buildPipelinePlugins(ctx, cfg, reg)
	if err != nil {
		return nil, nil, fmt.Errorf("pipeline plugins: %w", err)
	}

	engine := &pkgproxy.DefaultEngine{
		Resolver:        &proxy.AuthPrincipalResolver{Client: client, CookieName: cfg.CookieName},
		Policy:          adaptPolicyEngine(policyEngine),
		PipelinePlugins: pipelinePlugins,
		UpstreamURL:     cfg.UpstreamURL,
		RequireAuth:     bool(cfg.RequireAuth),
		Metrics:         metrics,
		Tracer:          tracer,
	}

	handler := httpserver.New(cfg, engine, reg, metricsHandler).Handler()
	return handler, tracerShutdown, nil
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
		return policy.NewWASMRuntime(fallback), nil
	}
}

func buildPipelinePlugins(ctx context.Context, cfg *config.Config, reg *plugin.Registry) ([]pkgproxy.PipelinePlugin, error) {
	if reg == nil || len(cfg.PipelinePlugins) == 0 {
		return nil, nil
	}

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
