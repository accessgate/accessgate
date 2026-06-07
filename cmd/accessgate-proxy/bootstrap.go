package main

import (
	"context"
	"fmt"
	"log"
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

func buildProxyHandler(ctx context.Context, cfg *config.Config) (http.Handler, pkgproxy.Engine, func(context.Context) error, error) {
	client := proxy.NewAuthClient(cfg.AuthURL, cfg.CookieName)

	reg := plugin.New()
	if err := (&register.Registrar{}).RegisterBuiltins(ctx, reg); err != nil {
		return nil, nil, nil, fmt.Errorf("register built-in plugins: %w", err)
	}
	if cfg.PluginsManifestDir != "" {
		if err := discoverManifests(ctx, cfg, reg); err != nil {
			return nil, nil, nil, err
		}
	}

	metrics, metricsHandler := observability.NewPrometheusMetrics(nil)
	tracer, tracerShutdown := observability.NewOTLPTracerFromEnvWithShutdown()
	policyEngine, policyStop, err := buildPolicyEngine(ctx, cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("policy engine: %w", err)
	}
	pipelinePlugins, err := buildPipelinePlugins(ctx, cfg, reg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pipeline plugins: %w", err)
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

	// Combine tracer and policy-hot-watcher shutdown into a single shutdown hook so
	// main.go's lifecycle code does not need to know about either independently.
	shutdown := func(sctx context.Context) error {
		if policyStop != nil {
			policyStop()
		}
		if tracerShutdown != nil {
			return tracerShutdown(sctx)
		}
		return nil
	}

	handler := httpserver.New(cfg, engine, reg, metricsHandler).Handler()
	return handler, engine, shutdown, nil
}

// manifestLogger is used for non-fatal manifest discovery diagnostics. It is a package var
// so behavior is consistent regardless of which entrypoint calls buildProxyHandler.
var manifestLogger = log.New(os.Stderr, "[accessgate-proxy][plugin] ", log.LstdFlags|log.LUTC)

// discoverManifests runs filesystem manifest discovery and dependency-graph assembly.
//
// Behavior is governed by cfg.PluginsManifestStrict:
//   - strict: any discovery or dependency-graph error aborts startup (fail-closed).
//   - non-strict (default): errors are logged clearly but startup proceeds, preserving the
//     previous best-effort behavior without silently dropping the errors.
//
// When cfg.PluginsManifestPublicKeyPath is set, an Ed25519 signature verifier is wired in and
// every manifest must carry a valid signature (fail-closed on bad/missing signatures).
func discoverManifests(ctx context.Context, cfg *config.Config, reg *plugin.Registry) error {
	var verifier plugin.Verifier
	if cfg.PluginsManifestPublicKeyPath != "" {
		v, err := plugin.NewEd25519VerifierFromFile(cfg.PluginsManifestPublicKeyPath)
		if err != nil {
			// A misconfigured/unreadable signing key is always fatal: we cannot honor the
			// operator's intent to verify manifests.
			return fmt.Errorf("plugin manifest verifier: %w", err)
		}
		verifier = v
	}

	if err := plugin.DiscoverFromDir(ctx, reg, cfg.PluginsManifestDir, verifier); err != nil {
		if cfg.PluginsManifestStrict {
			return fmt.Errorf("plugin manifest discovery (strict): %w", err)
		}
		manifestLogger.Printf("manifest discovery error (non-strict, continuing): %v", err)
		return nil
	}

	if err := reg.BuildDependencyGraph(); err != nil {
		if cfg.PluginsManifestStrict {
			return fmt.Errorf("plugin dependency graph (strict): %w", err)
		}
		manifestLogger.Printf("plugin dependency graph error (non-strict, continuing): %v", err)
		return nil
	}

	return nil
}

// buildPolicyEngine constructs the policy engine for the configured backend. When
// policy_reload_enabled is set (and a bundle path is configured), the engine is wrapped
// in a policy.HotWatcher that polls the bundle's mtime and reloads it in place
// (re-verifying the signature, fail-closed to last-good). The returned stop function is
// non-nil only when a watcher was started; callers must invoke it on shutdown.
func buildPolicyEngine(ctx context.Context, cfg *config.Config) (policy.Engine, func(), error) {
	fallback := policy.FallbackConfig{Allow: bool(cfg.PolicyFallbackAllow)}

	switch cfg.PolicyEngine {
	case config.PolicyEngineWASM:
		if cfg.PolicyBundlePath == "" {
			return policy.NewWASMRuntime(fallback), nil, nil
		}
		var publicKeyPEM string
		if cfg.BundlePublicKeyPath != "" {
			pem, err := os.ReadFile(cfg.BundlePublicKeyPath)
			if err != nil {
				return nil, nil, fmt.Errorf("read bundle public key %q: %w", cfg.BundlePublicKeyPath, err)
			}
			publicKeyPEM = string(pem)
		}
		// A single loader is reused across reloads so its mtime cache and verified-key
		// state persist; LoadBundle re-verifies the signature on every changed mtime.
		loader := policy.NewBundleLoader(fallback, publicKeyPEM)
		eng, err := loader.LoadBundle(cfg.PolicyBundlePath)
		if err != nil {
			return nil, nil, err
		}
		reload := func() (policy.Engine, error) { return loader.LoadBundle(cfg.PolicyBundlePath) }
		return maybeWrapHotWatcher(ctx, cfg, eng, reload)
	case config.PolicyEngineRego:
		eng := policy.NewRegoEngine(fallback)
		if cfg.PolicyBundlePath == "" {
			return eng, nil, nil
		}
		if err := eng.Load(cfg.PolicyBundlePath); err != nil {
			return nil, nil, err
		}
		// Rego reload re-compiles in place on the same engine instance; Load already
		// swaps the prepared query under its own lock, so we return the same engine.
		reload := func() (policy.Engine, error) {
			if err := eng.Load(cfg.PolicyBundlePath); err != nil {
				return nil, err
			}
			return eng, nil
		}
		return maybeWrapHotWatcher(ctx, cfg, eng, reload)
	default:
		return policy.NewWASMRuntime(fallback), nil, nil
	}
}

// maybeWrapHotWatcher wraps eng in a started policy.HotWatcher when hot-reload is
// enabled, returning the watcher (which itself satisfies policy.Engine) and a stop
// function. When disabled it returns eng unchanged with a nil stop function.
func maybeWrapHotWatcher(ctx context.Context, cfg *config.Config, eng policy.Engine, reload policy.ReloadFunc) (policy.Engine, func(), error) {
	if !cfg.PolicyReloadEnabled {
		return eng, nil, nil
	}
	interval := cfg.PolicyReloadIntervalDuration()
	watcher := policy.NewHotWatcher(cfg.PolicyBundlePath, interval, eng, reload, nil)
	watcher.Start(ctx)
	log.Printf("info: policy hot-reload enabled for %q every %s", cfg.PolicyBundlePath, interval)
	return watcher, watcher.Stop, nil
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
