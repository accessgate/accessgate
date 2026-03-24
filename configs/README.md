# Configurations

Example and template configuration files for AccessGate. Loading uses [go-config](https://pkg.go.dev/github.com/ArmanAvanesyan/go-config) v0.0.10+ (`config` loader, `providers/source/file`, `providers/source/env`, `providers/parser/json` or `providers/parser/yaml`) via `internal/configload`, then `internal/auth/config.Load` / `internal/proxy/config.Load` apply defaults and `Validate()`.

## Binary configs

- **auth.example.json** / **auth.example.yaml** — accessgate-auth (OIDC, session, cookie, Redis).
- **proxy.example.json** / **proxy.example.yaml** — accessgate-proxy (upstream, `auth_url`, header mapping, policy engine).

Optional **dev/prod variants** (YAML):

- **auth.dev.yaml**, **auth.prod.yaml** — auth service with dev- or prod-oriented defaults (e.g. `cookie_secure`, redirects).
- **proxy.dev.yaml**, **proxy.prod.yaml** — proxy with local vs production URLs.

## Plugin examples

- **plugins/caddy.Caddyfile**, **plugins/caddy.example.json** — Caddy forward-auth and optional directive.
- **plugins/traefik.example.yaml** — Traefik ForwardAuth dynamic config.
- **plugins/krakend.example.json** — KrakenD endpoint/auth plugin config.
- **plugins/ratelimit.example.json** — Proxy config enabling the `pipeline:ratelimit` rate-limit plugin.

## Usage

Use `CONFIG_PATH` or **`AUTH_CONFIG`** / **`PROXY_CONFIG`** to point at a config file. Deprecated: `AGENT_CONFIG` is still accepted for the auth service. Environment variables override file values (keys lowercase with underscores, e.g. `OIDC_ISSUER`). For the proxy, set **`AUTH_URL`** to match `auth_url` in the config file.

## Policy bundles (proxy)

The proxy can enforce policies via:

- **WASM**: `policy_engine: "wasm"` with `policy_bundle_path` pointing to a `.wasm` bundle
- **Rego (OPA embedded)**: `policy_engine: "rego"` with `policy_bundle_path` pointing to a `.rego` policy

Example Rego policies may live in external policy bundle repos. The decision contract uses **`package accessgate`** and query **`data.accessgate.decision`**.

## Tooling

From the repo root (see root `Makefile`):

- **validate-config** — Validate a config file (same load + `Validate()` as runtime):
  ```bash
  make validate-config CONFIG_PATH=configs/auth.example.json BINARY=auth
  make validate-config CONFIG_PATH=configs/proxy.dev.yaml BINARY=proxy
  ```
- **print-schema** — Print JSON Schema for a binary or plugin:
  ```bash
  make print-schema BINARY=auth
  make print-schema SCHEMA=schemas/plugins/integration/caddy.schema.json
  ```
- **render-config-example** — Render example config from defaults (go-config struct + `ApplyDefaults()`):
  ```bash
  make render-config-example BINARY=auth FORMAT=json
  make render-config-example BINARY=proxy FORMAT=json
  ```

`BINARY=agent` is accepted as a deprecated alias for `auth`.
