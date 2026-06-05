# AccessGate Architecture

> AccessGate is a policy-driven authentication and authorization runtime written in Go.
> The repository lives at `github.com/accessgate/accessgate`; the Go module path is
> currently `github.com/ArmanAvanesyan/accessgate` and is planned to be renamed to match
> the repository (see [`MIGRATION.md`](MIGRATION.md)). It separates **identity lifecycle**
> from **request-time enforcement** so each can scale, deploy, and fail independently.

This document describes how the system is put together: the two binaries and what they own,
the request and login lifecycles, the pluggable policy engine, the capability-based plugin
system, configuration, and observability. Every claim here is grounded in the code; file
paths are referenced inline so you can verify and extend them.

---

## 1. System Overview

AccessGate ships as two cooperating services:

| Binary | Source | Responsibility |
| --- | --- | --- |
| `accessgate-auth` | `cmd/accessgate-auth/main.go` | OIDC login/callback/refresh/logout, session issuance, JWKS validation, session resolution for the proxy. Owns all secrets and Redis state. |
| `accessgate-proxy` | `cmd/accessgate-proxy/main.go` | Request-time enforcement: resolves the caller's principal, runs pipeline plugins, evaluates policy, and emits the allow/deny decision plus upstream headers. |

They communicate over HTTP. The proxy never touches Redis or the IdP directly; it asks
`accessgate-auth` to turn a session cookie into a principal. See
[ADR-0002](adr/0002-auth-proxy-split.md) for the rationale.

```
                        Browser / Client
                              │
            login / callback  │  protected request (cookie)
        ┌─────────────────────┼──────────────────────────┐
        ▼                     │                           ▼
┌────────────────┐           │                 ┌────────────────────┐
│ accessgate-auth│           │                 │  accessgate-proxy  │
│                │           │                 │                    │
│ OIDC + PKCE    │           │  GET            │  principal resolve │
│ sessions       │◀──────────┼─ /internal/ ────│  pipeline plugins  │
│ JWKS validate  │  resolve  │  resolve        │  policy evaluate   │
│ signed cookies │──────────▶│                 │  decision→headers  │
└───────┬────────┘           │                 └─────────┬──────────┘
        │                     │                           │ allow
        ▼                     │                           ▼
     ┌──────┐                 │                     ┌───────────┐
     │ Redis│                 ▼                     │ Upstream  │
     │ sess │            Identity Provider          │ service   │
     │ pkce │            (OIDC: issuer, JWKS,        └───────────┘
     │ lock │             token, end-session)
     └──────┘
```

Shared, dependency-free building blocks live under `pkg/`:

- `pkg/oidc` — PKCE generation, discovery, token exchange, end-session URL (`pkg/oidc/*.go`).
- `pkg/token` — ID-token validation, JWKS source, claim normalization (`pkg/token/*.go`).
- `pkg/session` — `Session`, `PKCEState`, and the `SessionStore`/`PKCEStore`/`RefreshLockStore` interfaces (`pkg/session/*.go`).
- `pkg/cookie` — signed (and encrypted) cookie codecs (`pkg/cookie/signed.go`).
- `pkg/auth` — the `auth.Service` interface and request/response DTOs (`pkg/auth/api.go`).
- `pkg/observability` — Prometheus metrics, OTLP tracing, logging abstractions (`pkg/observability/*.go`).

---

## 2. The Proxy Request Lifecycle

The proxy's enforcement logic is `DefaultEngine.Handle` in `internal/authz/engine.go`. The
HTTP server (`internal/proxy/httpserver/server.go`) wires the engine behind the configured
`proxy_path_prefix` via `pkgproxy.Middleware`, and exposes `/healthz`, `/readyz`, `/livez`,
optional `/admin` (guarded by `X-Admin-Secret`), and optional `/metrics`.

```
incoming request (proxy_path_prefix)
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│ DefaultEngine.Handle  (internal/authz/engine.go)               │
│                                                                │
│ 1. principal resolve                                           │
│    Resolver.Resolve(req)  ──▶ proxy.AuthPrincipalResolver      │
│       └─ AuthClient.Resolve → GET {auth_url}/internal/resolve  │
│          with Cookie: {cookie_name}=<value>                    │
│       • resolve error      → 502 Bad Gateway                   │
│       • nil & RequireAuth  → 401 Unauthorized                  │
│                                                                │
│ 2. pipeline plugins (in order)                                 │
│    for each PipelinePlugin: Handle(req, principal)             │
│       • error             → 503 Service Unavailable            │
│       • non-nil Decision  → SHORT-CIRCUIT (skip policy)        │
│                                                                │
│ 3. policy evaluate (only if no plugin decided)                 │
│    Policy.Evaluate(policy.Input{protocol, method, path,        │
│       graphql_op, grpc_service/method, principal, headers})    │
│       • error             → 500 Internal Server Error          │
│                                                                │
│ 4. decision → response                                         │
│    • deny + Reason  → JSON {"errors":[{"message": reason}]}    │
│    • Decision.Headers copied to upstream headers               │
│    • obligations "set_header_*" → upstream headers (CRLF       │
│      stripped to prevent header injection)                     │
│    • if allow && principal: principal-derived headers added    │
│      (X-User-Id, X-Roles, Authorization: Bearer, X-User-Email, │
│       X-User-Full-Name, X-User-Preferred-Username, X-Tenant-Id)│
│    • Metrics.AuthDecision(allow, status_code)                  │
└───────────────────────────────────────────────────────────────┘
```

### Principal resolution

`proxy.AuthPrincipalResolver.Resolve` (`internal/proxy/resolver.go`) reads the session
cookie named by `cookie_name`, then calls `AuthClient.Resolve`
(`internal/proxy/authclient.go`), which issues `GET {auth_url}/internal/resolve` with the
session cookie attached. A `401` from auth means "no principal" (returns `nil`, not an
error). The JSON response (`access_token`, `claims`, `tenant_context`) is mapped into a
`token.Principal` — subject, roles, claims, expiry, access token, and tenant context — via
`resolveResponseToPrincipal`, normalizing claims through `token.NormalizeClaims`.

> Note: `accessgate-auth` exposes a browser-facing `GET /session` endpoint as well
> (`internal/auth/httpserver/server.go`), used by front ends to read the current user.
> The proxy uses the dedicated `GET /internal/resolve` endpoint, which additionally returns
> the access token and tenant context needed to build upstream headers.

### Pipeline short-circuit

Pipeline plugins run before policy. If any plugin returns a non-nil `*policy.Decision`, the
engine uses that decision and skips the main policy engine entirely (a rate-limiter denying
a request is the canonical example). A plugin error fails closed with `503`. See
[ADR-0003](adr/0003-capability-based-plugin-system.md).

### Decision to response

The engine maps `policy.Decision` to the proxy `Response`:

- `Decision.Headers` (a `map[string]string`) are copied verbatim to upstream headers.
- Obligations whose key starts with `set_header_` become upstream headers: the prefix is
  stripped and underscores become dashes (e.g. `set_header_X_Tenant` → `X-Tenant`). Both
  the name and value have CR/LF stripped to prevent header injection.
- When the decision is **allow** and a principal exists, `defaultHeaderBuilder` adds the
  identity headers listed above (overridable via `HeaderBuilder`).

---

## 3. The Auth Lifecycle

`accessgate-auth` implements the OIDC Authorization Code flow with PKCE. The service logic
is `internal/auth/service/service.go`; HTTP routing is `internal/auth/httpserver/server.go`.
Redis backs three stores constructed in `cmd/accessgate-auth/main.go`: the `SessionStore`,
`PKCEStore`, and `RefreshLockStore`.

```
LOGIN START  (GET /login?redirect_to=…)
  validate redirect → GeneratePKCE(verifier, challenge, nonce) → GenerateState
  PKCEStore.Set(state → {verifier, challenge, nonce, redirect_to})  (PKCE TTL)
  provider.AuthorizationURL(state, challenge, nonce) → 302 to IdP

CALLBACK     (GET|POST /callback?code&state)
  PKCEStore.Get(state) → delete   (one-time use)
  provider.ExchangeCode(code, verifier, redirect_uri) → raw OIDC tokens
  token.ValidateIDToken(id_token, JWKS, issuer, audience, nonce)
  session = {access, refresh, id_token, expires_at, claims}
  SessionStore.Set(session_id → session)  (session TTL)
  optional HMAC-signed post-login webhook (https only)
  cookie = signed(session_id) → Set-Cookie → 302 to redirect_to

REFRESH      (GET /refresh)
  decode cookie → SessionStore.Get
  if !NeedsRefresh(early window): no-op
  RefreshLockStore.Obtain(session_id)  (single-flight; skip if not acquired)
  provider.Refresh(refresh_token) → rotate tokens, re-validate id_token (no nonce)
  SessionStore.Set → refreshed cookie

LOGOUT       (GET|POST /logout)
  CSRF check (Origin/Referer vs allowed) → SessionStore.Delete
  provider.EndSessionURL(id_token_hint, post_logout_redirect) → 302; clear cookie
```

Key properties grounded in the code:

- **PKCE + state** are generated per login and stored in Redis keyed by `state`, then
  consumed exactly once on callback (`PKCEStore.Get` followed by `Delete`).
- **ID-token validation** (`token.ValidateIDToken`) checks issuer, audience (falling back
  to `oidc_client_id` when `oidc_audience` is empty), and nonce. Nonce is intentionally
  skipped on refresh per OIDC Core §12.2.
- **Sessions are server-side**: the cookie carries only a signed, opaque session ID
  (256-bit random, `generateSessionID`); the tokens and claims live in Redis.
- **Cookies are signed** by `cookie.NewSignedManager(cookie_signing_secret)` and set with
  `HttpOnly`, configurable `Secure`/`SameSite`/`Domain`, and the session TTL as `Max-Age`.
- **Refresh is single-flight**: `RefreshLockStore.Obtain` prevents a thundering herd of
  concurrent refreshes for the same session; refresh tokens are rotated when the IdP
  returns a new one.
- **JWKS** keys are fetched and cached by `token.NewHTTPJWKSSource` (5-minute TTL),
  recording cache hit/miss metrics per issuer.

---

## 4. The Policy Engine

Policy evaluation is abstracted behind `policy.Engine` (`internal/policy/engine.go`). The
proxy selects an implementation at startup from config (`buildPolicyEngine` in
`cmd/accessgate-proxy/main.go`):

| `policy_engine` | Implementation | Bundle |
| --- | --- | --- |
| `rego` | `policy.NewRegoEngine` (`internal/policy/rego.go`), OPA embedded (`open-policy-agent/opa/v1`) | `.rego` file via `Load` |
| `wasm` (default) | `policy.NewWASMRuntime` / `BundleLoader` (`internal/policy/wasm.go`, `internal/policy/bundle.go`), executed on `wazero` | `.wasm` file via signed bundle loader |

See [ADR-0001](adr/0001-rego-and-wasm-policy-engines.md) for why both exist.

### Shared decision contract

Both engines consume the same `policy.Input` (`internal/policy/input.go`) and return the
same `policy.Decision` shape `{ allow, status_code, reason, headers, obligations }`.

- **Rego**: the policy must declare `package accessgate`, and the engine evaluates the query
  `data.accessgate.decision`. The result object is decoded into `Decision` by
  `decisionFromAny`.
- **WASM**: the module must export a linear `memory` and an `evaluate(input_ptr, input_len)
  -> (output_ptr, output_len)` function. Input and output are JSON; the output is decoded
  into the same `Decision` fields.

### Signed bundles (WASM)

`BundleLoader` (`internal/policy/bundle.go`) compiles `.wasm` bundles on a shared `wazero`
runtime and caches them by path + file mtime, recompiling automatically when the file
changes. It accepts a PEM public key (`bundle_public_key_path`) for signature verification;
when no key is configured it logs a warning that integrity checks are disabled.

### Fail-closed by default

Every engine has a `FallbackConfig`. When no policy is loaded or evaluation fails (compile
error, empty result, malformed output, runtime error), the engine returns the fallback
decision rather than propagating the error. The default fallback is **deny with 503**
(`policy unavailable`); allow requires an explicit `policy_fallback_allow: true`. If the
engine somehow returns `nil`, `DefaultEngine.Handle` also defaults to deny/503. This makes
"unknown" mean "blocked".

---

## 5. The Plugin System

The plugin contracts live in `internal/plugin/api.go`. AccessGate supports three kinds of
plugins:

| Kind (`PluginKind`) | Interface | Role |
| --- | --- | --- |
| `pipeline` | `PipelinePlugin` | Participate in the proxy request pipeline; may short-circuit with a `Decision`. Example capability `pipeline:ratelimit`. |
| `provider` | `ProviderPlugin` | Drive an IdP: authorization URL, code exchange, refresh, end-session. Example `provider:oidc`. |
| `integration` | `IntegrationPlugin` | Attach the proxy engine to a host gateway (Caddy, Traefik, KrakenD). Example `integration:krakend`. |

**Capabilities** are symbolic strings (`Capability`) such as `pipeline:ratelimit` or
`provider:oidc`. A plugin's `PluginDescriptor` advertises the capabilities it provides and
those it `DependsOn`, which the registry uses to build a dependency/startup graph.

**Lifecycle** is expressed by `PluginState`: `discovered → verified → registered →
configured → initialized → started → healthy` (with `degraded` / `stopped` as terminal-ish
states). Optional interfaces gate transitions: `ConfigurablePlugin.Configure`,
`StartablePlugin.Start`/`Stop`, and `Plugin.Health` for runtime health reporting (surfaced
on `/admin` and as the `accessgate_plugin_health_state` gauge).

**Discovery**:

- *Built-ins* are compiled into the binary and registered by `register.Registrar`
  (`internal/plugins/register/registrar.go`) — currently the rate-limit pipeline plugin and
  the OIDC provider plugin.
- *Manifest discovery* (`plugin.DiscoverFromDir`, `internal/plugin/discovery.go`) walks
  `plugins_manifest_dir` for JSON manifests describing plugin ID/kind/capabilities/
  dependencies (with optional signature metadata), then `BuildDependencyGraph` orders them.

The proxy instantiates configured pipeline plugins in `buildPipelinePlugins`
(`cmd/accessgate-proxy/main.go`): look up the registration by ID, run the factory,
`Configure` then `Start` if the plugin implements those interfaces, and assert it satisfies
`PipelinePlugin`. The provider plugin for auth is built similarly in `buildProviderPlugin`
(`cmd/accessgate-auth/main.go`). See [ADR-0003](adr/0003-capability-based-plugin-system.md).

---

## 6. Configuration

Both binaries load configuration through the same pipeline: `configload.LoadInto`
(`internal/configload/load.go`) built on `go-config`. An optional file (JSON or YAML, chosen
by extension) is merged with **all environment variables**, and **later sources win — env
overrides file**. Each binary then calls `ApplyDefaults` and `Validate`.

### Config-path resolution

| Binary | Resolution order (`loadConfig`) |
| --- | --- |
| `accessgate-auth` | `CONFIG_PATH` → `AUTH_CONFIG` → `AGENT_CONFIG` (deprecated alias) |
| `accessgate-proxy` | `CONFIG_PATH` → `PROXY_CONFIG` |

If none is set, the loader runs with environment variables only. The `AGENT_CONFIG` name and
the `agent`→`auth` aliasing in the Makefile are retained for backward compatibility. See
[ADR-0004](adr/0004-config-file-plus-env.md).

### Notable settings

- **Auth** (`internal/auth/config/config.go`): `oidc_issuer`, `oidc_client_id/secret`,
  `oidc_redirect_uri`, `oidc_scopes` (comma string or array), `redis_url`, session TTLs,
  `cookie_name`, `cookie_signing_secret`, `cookie_secure/same_site/domain`. Booleans accept
  both real booleans and string forms via `FlexibleBool`.
- **Proxy** (`internal/proxy/config/config.go`): `upstream_url`, `proxy_path_prefix`
  (default `/graphql`), `require_auth`, `auth_url`, `cookie_name` (default
  `__Host-ess_session`), `policy_engine` (default `wasm`), `policy_bundle_path`,
  `policy_fallback_allow` (default **deny**), `bundle_public_key_path`, `pipeline_plugins`,
  `plugins_manifest_dir`, `admin_secret`, and the `headers_*_claim` mapping. The proxy
  enforces SSRF protection on `upstream_url` (blocks loopback/RFC-1918/link-local) unless
  `allow_private_upstreams: true`.

### Schema generation

`make schema` runs `cmd/schema/main.go`, which uses the go-config schema extension to emit
`schemas/auth.schema.json` and `schemas/proxy.schema.json` from the Go config structs.
Related Makefile targets: `validate-config`, `print-schema`, and `render-config-example`.

---

## 7. Observability

Both binaries wire observability in `main` via `pkg/observability`.

### Metrics (Prometheus)

`observability.NewPrometheusMetrics` (`pkg/observability/prometheus.go`) registers the
`accessgate_*` series and returns a `/metrics` handler:

| Metric | Type | Labels |
| --- | --- | --- |
| `accessgate_auth_decisions_total` | counter | `result` (allow/deny), `status_code` |
| `accessgate_jwks_cache_operations_total` | counter | `issuer`, `result` (hit/miss) |
| `accessgate_session_store_operations_total` | counter | `operation`, `result` |
| `accessgate_plugin_health_state` | gauge | `plugin_id` (1 healthy / 0.5 degraded / 0 stopped) |
| `accessgate_agent_flow_operations_total` | counter | `operation` (login_start/login_end/refresh/logout), `result` |

### Tracing (OTLP)

`observability.NewOTLPTracerFromEnvWithShutdown` (`pkg/observability/otel_tracer.go`) is
**env-driven and best-effort**: it activates only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
(honoring `OTEL_EXPORTER_OTLP_PROTOCOL` grpc/http and `OTEL_SERVICE_NAME`, default
`accessgate`). Init failure degrades silently to a no-op tracer so auth flows are never
interrupted, and a shutdown hook flushes batched spans on exit. Span attributes are length-
capped and keys that look sensitive (`token`, `secret`, `authorization`, …) are dropped.

The proxy emits spans around the request flow (`proxy.handle`, `proxy.principal_resolve`,
`proxy.pipeline_plugin`, `proxy.policy_evaluate`, `proxy.upstream_build`); the auth service
emits spans across the login/refresh/logout flows.

---

## 8. Where to Look Next

- Request enforcement: `internal/authz/engine.go`
- Auth flows: `internal/auth/service/service.go`, `internal/auth/httpserver/server.go`
- Policy engines: `internal/policy/{rego,wasm,bundle}.go`
- Plugin contracts: `internal/plugin/api.go`, registration `internal/plugins/register`
- Config: `internal/configload/load.go`, `internal/{auth,proxy}/config`
- Architecture decisions: [`docs/adr/`](adr/)
