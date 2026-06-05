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
Update import paths to `github.com/accessgate/accessgate/...`. The previous
`github.com/ArmanAvanesyan/accessgate` path is superseded.

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

## Repository pointers

- Canonical core: **`accessgate/accessgate`**
- Legacy ancestor (archived, read-only): **`accessgate/authsentinel`**
  (the `ArmanAvanesyan/authsentinel` copy is an archived duplicate — do not use it)
- PolicyFront-era ecosystem repos: **archived** (see [`REPO-MAP.md`](REPO-MAP.md))

## Need help?

Open a `legacy-migration` issue using the template in `.github/ISSUE_TEMPLATE/`.
