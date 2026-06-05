# ADR-0003: Capability-based plugin system

- **Status**: Accepted
- **Date**: 2026-06-05

## Context

AccessGate needs to be extended along several independent axes — new identity providers, new
request-time behaviors (rate limiting, header shaping), and new gateway integrations —
without forking the core. These extension points have different shapes and different
lifecycle needs, and some depend on others being present. We want a uniform way to describe,
register, order, configure, and health-check them.

## Decision

We define a small set of plugin contracts in `internal/plugin/api.go`.

**Kinds** (`PluginKind`) classify a plugin and map to a behavioral interface:

- `pipeline` → `PipelinePlugin` — participates in the proxy request pipeline via
  `Handle(ctx, req, principal) (*policy.Decision, error)`.
- `provider` → `ProviderPlugin` — drives an IdP (authorization URL, code exchange, refresh,
  end-session).
- `integration` → `IntegrationPlugin` — attaches the proxy engine to a host gateway.

**Capabilities** are symbolic strings (`Capability`) such as `pipeline:ratelimit`,
`provider:oidc`, or `integration:krakend`. A `PluginDescriptor` advertises the capabilities a
plugin provides and the ones it `DependsOn`, which the registry uses to build a dependency
and startup graph.

**Lifecycle** is modeled by `PluginState`: `discovered → verified → registered → configured
→ initialized → started → healthy`, with `degraded` and `stopped` for runtime conditions.
Transitions are gated by optional interfaces — `ConfigurablePlugin.Configure`,
`StartablePlugin.Start`/`Stop` — and `Plugin.Health` reports runtime health (surfaced on
`/admin` and via the `accessgate_plugin_health_state` gauge).

**Registration** has two paths: built-ins compiled into the binary
(`internal/plugins/register/registrar.go`, currently rate-limit and OIDC provider) and
manifest discovery from `plugins_manifest_dir` (`internal/plugin/discovery.go`, JSON
manifests with optional signature metadata, ordered by `BuildDependencyGraph`).

**Pipeline short-circuit semantics**: in `DefaultEngine.Handle`
(`internal/authz/engine.go`), pipeline plugins run in order *before* the main policy engine.
If a plugin returns a non-nil `*policy.Decision`, the engine uses it and skips policy
evaluation entirely; a plugin error fails closed with `503`. This lets a plugin (e.g. a
rate limiter) deny early without invoking policy.

## Consequences

- A single, uniform model covers three distinct extension axes; the core stays closed while
  behavior stays open.
- Capabilities + `DependsOn` give the registry enough information to order startup and to
  reason about missing dependencies, rather than relying on registration order.
- The lifecycle states and optional interfaces let plugins opt into only the hooks they need
  and report health uniformly.
- Pipeline short-circuit keeps cross-cutting concerns (rate limiting, fast denies) cheap by
  avoiding policy evaluation when a plugin has already decided.
- Cost: the descriptor/capability/lifecycle vocabulary is a public contract that must remain
  stable; manifest-discovered plugins in v1 still require a host-provided factory for their
  implementation.
