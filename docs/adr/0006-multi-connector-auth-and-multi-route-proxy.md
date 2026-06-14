# ADR-0006: Multi-connector auth and multi-route proxy

- **Status**: Accepted
- **Date**: 2026-06-14

## Context

ADR-0002 split AccessGate into `accessgate-auth` (identity lifecycle) and `accessgate-proxy`
(request-time enforcement). In practice each of those still assumed a single identity provider
and a single upstream, which forced operators to run one deployment per provider and one per
upstream. A representative stack needed **four** processes:

- `accessgate-auth` — primary SSO (OIDC)
- `accessgate-auth-telegram` — Telegram OIDC, a second provider
- `accessgate-proxy` — the GraphQL/API upstream
- `accessgate-proxy-web` — the HTML host upstream

That duplication came from missing platform capabilities, not from real isolation needs:

1. No way to host more than one connector in one auth instance.
2. No way to protect more than one route/upstream in one proxy instance.
3. No first-class connector handoff artifact (browser cookie → edge header glue was fragile).
4. No connector-specific identity mapping — `sub` was the only authoritative id, but Telegram's
   authoritative downstream id is a numeric id, not an OIDC `sub`.

We want to collapse the split topology into one auth service and one proxy, without a hard reset
of existing deployments or sessions.

## Decision

We make connectors and routes first-class, configured as lists, with full backward compatibility.

### One auth instance, many connectors

`internal/auth/config.Config` gains `connectors[]` (`ConnectorConfig`): per-connector id,
issuer/discovery, client credentials, callback path (`oidc_redirect_uri`), session/cookie
namespace, and a `claim_mapping` policy. When `connectors` is empty, `Config.Normalize()`
synthesizes a single `default` connector from the legacy top-level `oidc_*` fields, preserving the
existing Redis prefix (`auth:session:` …) and cookie name (`__Host-ess_session`) **byte-for-byte**.

The auth service (`internal/auth/service`) holds `map[connectorID]*connector`; each connector owns
its own provider plugin instance and Redis-namespaced stores (same Redis server, distinct key
prefix — no extra Redis or auth deployment needed for isolation). Connector selection is via a
**path segment**: `/login/{connector}`, `/callback/{connector}`, `/logout/{connector}`,
`/refresh/{connector}`, `/session/{connector}`. The legacy unsegmented paths map to the default
connector. Each connector has its own cookie name (default keeps the legacy name; others get
`__Host-ess_session_<id>`), so connectors are independent cookie/session namespaces. The proxy's
`/internal/resolve` accepts an optional `?connector=<id>`.

### Connector-specific identity normalization

`ConnectorConfig.ClaimMapping` selects the authoritative downstream id. `LoginEnd` resolves it
(`authoritative_id_claim`, default `sub`; numeric claims like Telegram's id are coerced to string)
and stores it as `claims["sub"]` plus `authoritative_id_kind`. Carrying the chosen id in
`claims["sub"]` means it flows unchanged through `/internal/resolve` to the proxy's `X-User-Id`
header with no downstream changes. On refresh, the established id is preserved when a refreshed
token omits the authoritative claim.

### First-class signed handoff ticket

`internal/auth/handoff` issues a signed, short-lived (≈120s), one-time ticket binding
`{connector, authoritative id, session ref, iat/exp, jti}`. Tickets are HMAC-signed with the
cookie signing secret and redeemed exactly once via an atomic Redis `SETNX` consume (fail-closed
if the store is unavailable). `POST /internal/handoff/issue` (admin) mints a ticket for a user's
existing connector session; `GET /handoff/redeem/{connector}?ticket=…` (public — the signed ticket
is the credential) sets the connector cookie and 302s to a validated target. This replaces fragile
cookie→edge glue for connector handoff (e.g. Telegram bot → web session).

### One proxy instance, many routes

`internal/proxy/config.Config` gains `routes[]` (`RouteConfig`): host/path matchers, per-route
upstream, per-route `require_auth`, per-route `unauthenticated_mode` (`api_401` default, or
`html_redirect` with `login_redirect_url`), and the `connector_id` to resolve against. When `routes`
is empty, `Normalize()` synthesizes a single `default` route from legacy `upstream_url` /
`proxy_path_prefix`. The proxy builds one `DefaultEngine` per route (sharing policy engine,
pipeline plugins, metrics, tracer) and dispatches on host + longest-path-prefix; unmatched
requests return 404. `DefaultEngine` adds an `html_redirect` mode that returns a 302 to the login
URL instead of a JSON 401.

### Trust boundary

`ProxyToUpstream` now strips the full set of client-supplied identity headers (`X-User-Id`,
`X-Roles`, `X-User-Email`, `X-User-Full-Name`, `X-User-Preferred-Username`, `X-Is-Admin`,
`X-Tenant-Id`, `Authorization`) before re-injecting the proxy's verified, principal-derived
values — closing a spoofing gap that existed whenever the proxy did not itself overwrite a header.

### Observability

New low-cardinality counters: `accessgate_auth_callbacks_total{connector_id,result}`,
`accessgate_auth_handoff_total{operation,connector_id,result}`,
`accessgate_proxy_route_outcomes_total{route,outcome}` (allow / auth_failure / upstream_failure /
route_miss), plus `connector`/`route`/`id_kind` tracing-span attributes.

## Consequences

- One `accessgate-auth` hosts primary SSO + Telegram (and more) without extra deployments; one
  `accessgate-proxy` serves the HTML host and the GraphQL/API upstream. Adding a connector or
  route is a config entry, not a cloned stack.
- Backward compatible: existing single-provider / single-upstream configs keep working unchanged
  (a default connector/route is synthesized), so the split stacks can be collapsed incrementally
  with no Redis flush — the default connector preserves the legacy cookie and key prefixes, and a
  migrated Telegram connector reuses its old `session_redis_prefix` to retain live sessions. See
  `docs/MIGRATION.md`.
- New obligations: `connectors[]`/`routes[]` are the only optional top-level config keys (the
  schema generator marks everything else required); `make schema` must be re-run after config
  struct changes. Per-route policy-bundle overrides are not yet wired (all routes share the engine
  unless extended later). Handoff replay protection depends on Redis availability and fails closed.
- The signed-handoff and connector-cookie conventions become a contract the auth and proxy sides
  must keep in sync (the proxy derives a connector's cookie name as `<legacy>_<id>`).
