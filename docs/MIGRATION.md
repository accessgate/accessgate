# Migrating to AccessGate (from AuthSentinel / PolicyFront)

AccessGate is the current canonical product. It descends from two earlier
phases (see [`LINEAGE.md`](LINEAGE.md)):

1. **AuthSentinel** — the original integrated monorepo/runtime.
2. **PolicyFront** — an intermediate phase that split the ecosystem (SDKs,
   plugins, bundles, packaging, playground) into separate repos.
3. **AccessGate** — the current core runtime and product center.

If you ran AuthSentinel- or PolicyFront-named artifacts, this guide lists what
changed and how to update.

## What changed

| Area | Old (AuthSentinel / PolicyFront) | New (AccessGate) |
|------|----------------------------------|------------------|
| Go module path | `github.com/ArmanAvanesyan/accessgate` (and earlier monorepo paths) | `github.com/accessgate/accessgate` |
| Binaries | `policyfront-agent`, `policyfront-proxy` (and `*-agent` naming) | `accessgate-auth`, `accessgate-proxy` |
| Prometheus metrics prefix | `policyfront_*` (e.g. `policyfront_auth_decisions_total`) | `accessgate_*` (e.g. `accessgate_auth_decisions_total`) |
| Default OTEL service name | `policyfront` | `accessgate` (when `OTEL_SERVICE_NAME` is unset) |
| Rego package / query | `package policyfront` / `data.policyfront.decision` | `package accessgate` / `data.accessgate.decision` |
| Protobuf packages | `policyfront.*` | `accessgate.*` (e.g. `accessgate.auth.v1`, `accessgate.sdk.v1`) |
| Auth config env var | `AGENT_CONFIG` | `AUTH_CONFIG` (or `CONFIG_PATH`) |

## Migration steps

### 1. Imports (if you import the Go packages)
The module path is `github.com/accessgate/accessgate/...` (matching the
repository). The rename from `github.com/ArmanAvanesyan/accessgate` has landed on
`main`; import from `github.com/accessgate/accessgate/...`.

### 2. Binaries & deployment
Replace `policyfront-agent` → `accessgate-auth` and `policyfront-proxy` →
`accessgate-proxy` in your process managers, Dockerfiles, Helm values, and
systemd units. The proxy reads the auth base URL from `auth_url`.

### 3. Configuration
- Prefer `CONFIG_PATH`; otherwise `accessgate-auth` reads `AUTH_CONFIG` and
  `accessgate-proxy` reads `PROXY_CONFIG`.
- `AGENT_CONFIG` is still accepted by `accessgate-auth` as a **deprecated**
  fallback — migrate to `AUTH_CONFIG`.
- Config is file (JSON or YAML) **plus** environment variables, where **env
  overrides file**. Regenerate/inspect the schema with `make print-schema BINARY=auth|proxy`.
- See `configs/*.example.{json,yaml}` for current shapes.

### 4. Policies
Rename your Rego package to `package accessgate` and ensure the runtime queries
`data.accessgate.decision`. The decision object shape is unchanged:
`{ allow, status_code, reason, headers, obligations }`. For WASM, rebuild bundles
and (recommended) sign them, configuring `bundle_public_key_path`.

### 5. Observability
Update dashboards/alerts from `policyfront_*` to `accessgate_*` metric names.
If you relied on the default OTEL service name, set `OTEL_SERVICE_NAME`
explicitly during transition to avoid breaking trace queries.

### 6. SDKs, plugins, and packaging
The SDKs (web, Go, Node, React, TypeScript, Flutter, …), gateway plugins
(Caddy, Traefik, KrakenD), and packaging (Docker/Helm) live in the ecosystem
repos. The PolicyFront-era ecosystem repos (`policyfront/*`) are **archived /
read-only** historical lineage — consume current ecosystem artifacts from their
maintained homes, not the archived repos.

## Collapsing split stacks: multi-connector auth & multi-route proxy

As of ADR-0006, one `accessgate-auth` hosts multiple **connectors** and one
`accessgate-proxy` serves multiple **routes**. This lets you collapse a split
topology (e.g. `accessgate-auth` + `accessgate-auth-telegram` +
`accessgate-proxy` + `accessgate-proxy-web`) into two processes. It is fully
backward compatible: a config with no `connectors`/`routes` keeps working
unchanged (a `default` connector/route is synthesized from the legacy
`oidc_*` / `upstream_url` fields).

### Translate the configs

Auth — merge the two single-provider configs into one `connectors` list:

```json
{
  "redis_url": "redis://redis:6379",
  "cookie_signing_secret": "…",
  "app_base_url": "https://portal.example.com",
  "connectors": [
    { "id": "sso", "default": true,
      "oidc_issuer": "https://idp.example.com",
      "oidc_client_id": "portal", "oidc_client_secret": "…",
      "oidc_redirect_uri": "https://portal.example.com/callback/sso" },
    { "id": "telegram",
      "oidc_issuer": "https://tg-oidc.example.com",
      "oidc_client_id": "tg", "oidc_client_secret": "…",
      "oidc_redirect_uri": "https://portal.example.com/callback/telegram",
      "session_redis_prefix": "telegram",
      "claim_mapping": { "authoritative_id_claim": "tg_id", "id_kind": "telegram_id" } }
  ]
}
```

Set the Telegram connector's `session_redis_prefix` to the **old prefix used by
the `accessgate-auth-telegram` deployment** so its existing sessions survive the
move (no Redis flush). The `default` connector keeps the legacy cookie name, so
primary SSO users are not logged out.

Proxy — turn the two upstreams into `routes`:

```json
{
  "auth_url": "http://accessgate-auth:8080",
  "routes": [
    { "id": "web", "path_prefix": "/", "upstream_url": "http://web:3000",
      "require_auth": true, "unauthenticated_mode": "html_redirect",
      "login_redirect_url": "https://portal.example.com/login", "connector_id": "sso" },
    { "id": "api", "path_prefix": "/graphql", "upstream_url": "http://api:4000",
      "require_auth": true, "unauthenticated_mode": "api_401", "connector_id": "sso" }
  ]
}
```

The proxy derives a connector's cookie name as `<cookie_name>_<connector_id>`
(the default connector uses the bare `cookie_name`), matching the auth side.

### Rollout order (no hard reset)

1. Ship the new binaries to all four deployments with **unchanged** config and
   verify parity (the synthesized default connector/route reproduces today's
   behavior). Reversible.
2. Deploy the unified auth with `connectors`, alongside the old auth
   deployments, and shift traffic gradually — sessions survive via preserved
   prefixes/cookies.
3. Deploy the unified proxy with `routes`, alongside the old proxies, until
   verified.
4. Decommission `accessgate-auth-telegram` and `accessgate-proxy-web`.

### Connector handoff

For flows that authenticate on one connector and need to hand a browser into the
web session (e.g. a Telegram bot → web), use the signed one-time handoff ticket:
`POST /internal/handoff/issue` (admin) returns a `redeem_url`; the browser visits
`GET /handoff/redeem/{connector}?ticket=…` which sets the connector cookie and
redirects. Tickets are short-lived, HMAC-signed, and redeemable once.

## Repository pointers

- Canonical core: **`accessgate/accessgate`**
- Legacy ancestor (archived, read-only): **`accessgate/authsentinel`**
  (the `ArmanAvanesyan/authsentinel` copy is an archived duplicate — do not use it)
- PolicyFront-era ecosystem repos: **archived** (see [`REPO-MAP.md`](REPO-MAP.md))

## Need help?

Open a `legacy-migration` issue using the template in `.github/ISSUE_TEMPLATE/`.
