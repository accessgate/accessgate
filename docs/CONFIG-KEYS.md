# Configuration keys

This document describes every configuration key for the two AccessGate core
binaries, `accessgate-auth` and `accessgate-proxy`. It is derived from the Go
config structs and their `Validate()` / `ApplyDefaults()` logic:

- `internal/auth/config/config.go`
- `internal/proxy/config/config.go`

Config is loaded from an optional file (JSON or YAML) merged with environment
variables, with **environment variables overriding file values**. Keys use
lowercase-with-underscores in files (e.g. `oidc_issuer`) and the equivalent
UPPER_SNAKE_CASE as environment variables (e.g. `OIDC_ISSUER`).

JSON Schemas generated from these structs live in `schemas/auth.schema.json`
and `schemas/proxy.schema.json`. Regenerate them with `make schema`; validate a
config file with `make validate-config CONFIG_PATH=<file> BINARY=auth|proxy`.

## Config file path resolution

Each binary resolves the config file path from environment variables in order:

| Binary             | Env var precedence                                           |
| ------------------ | ------------------------------------------------------------ |
| `accessgate-auth`  | `CONFIG_PATH` → `AUTH_CONFIG` → `AGENT_CONFIG` (deprecated)   |
| `accessgate-proxy` | `CONFIG_PATH` → `PROXY_CONFIG`                                |

If none is set, the loader runs with environment variables only.

> **Deprecated:** `AGENT_CONFIG` is a deprecated alias for `AUTH_CONFIG`,
> retained for backward compatibility with the pre-rename `agent` service. New
> deployments should use `AUTH_CONFIG` (or `CONFIG_PATH`). Similarly,
> `BINARY=agent` is accepted by `make validate-config` as a deprecated alias for
> `BINARY=auth` and emits a deprecation warning.

## Value type notes

- **flexible bool** — accepts a JSON/YAML boolean (`true`) or a string form
  (`"true"`, `"1"`, `"yes"`, `"y"`, `"false"`, `"0"`, `"no"`, `"n"`). Useful for
  env-var loaders that only produce strings.
- **comma list** — accepts either a JSON/YAML array (`["openid", "profile"]`) or
  a single comma-separated string (`openid,profile`), convenient for env vars.

---

## accessgate-auth

Source: `internal/auth/config/config.go`. "Required" means `Validate()` returns
an error if the value is empty. "Default" is applied by `ApplyDefaults()` when
the value is empty/zero.

### OIDC

| Key                  | Type        | Required | Default      | Description |
| -------------------- | ----------- | -------- | ------------ | ----------- |
| `oidc_issuer`        | string      | **yes**  | —            | OIDC issuer URL used for discovery. |
| `oidc_redirect_uri`  | string      | **yes**  | —            | Redirect/callback URI registered with the IdP. |
| `oidc_client_id`     | string      | **yes**  | —            | OIDC client ID. |
| `oidc_client_secret` | string      | no       | —            | OIDC client secret. Set via the `OIDC_CLIENT_SECRET` env var; the literal value `your-client-secret` is rejected as a placeholder. |
| `oidc_scopes`        | comma list  | no       | `["openid","profile"]` | OAuth2/OIDC scopes to request. |
| `oidc_audience`      | string      | no       | —            | Expected audience claim, if enforced. |
| `oidc_claims_source` | string      | no       | `id_token`   | Where claims are read from: `id_token` or `access_token`. Any other value is coerced to `id_token`. |

### Redis / session

| Key                                 | Type   | Required | Default | Description |
| ----------------------------------- | ------ | -------- | ------- | ----------- |
| `redis_url`                         | string | **yes**  | —       | Redis connection URL (e.g. `redis://localhost:6379`) for session storage. |
| `session_redis_prefix`              | string | no       | `auth`  | Key prefix for session/PKCE/lock/revoked/replay keys in Redis. |
| `session_ttl_seconds`               | int    | no       | `36000` | Session lifetime in seconds. |
| `session_pkce_ttl_seconds`          | int    | no       | `300`   | TTL for stored PKCE/login-flow state in seconds. |
| `session_refresh_lock_ttl_seconds`  | int    | no       | `15`    | TTL of the distributed lock taken during token refresh. |
| `session_refresh_early_seconds`     | int    | no       | `60`    | Refresh access tokens this many seconds before expiry. |

### Cookie

| Key                     | Type          | Required | Default              | Description |
| ----------------------- | ------------- | -------- | -------------------- | ----------- |
| `cookie_name`           | string        | no       | `__Host-ess_session` | Session cookie name. |
| `cookie_signing_secret` | string        | **yes**  | —                    | Secret used to sign the session cookie. Set via the `COOKIE_SIGNING_SECRET` env var; the literal value `CHANGE-ME-in-production` is rejected as a placeholder. |
| `cookie_secure`         | flexible bool | no       | `false`              | Sets the `Secure` cookie attribute. Use `true` in production (HTTPS). |
| `cookie_same_site`      | string        | no       | `lax`                | `SameSite` policy: `strict`, `none`, or `lax`. Any other value (including empty) maps to `lax`. Parsed into the internal `cookie_same_site` runtime field. |
| `cookie_domain`         | string        | no       | —                    | Cookie `Domain` attribute; empty for host-only cookies. |

### App and redirects

| Key                         | Type       | Required | Default                     | Description |
| --------------------------- | ---------- | -------- | --------------------------- | ----------- |
| `app_base_url`              | string     | **yes**  | —                           | Base URL of the application/portal. |
| `login_error_redirect_path` | string     | no       | `/login?error=oidc_error`   | Path to redirect to on login/OIDC error. |
| `allowed_redirect_origins`  | comma list | no       | —                           | Allow-list of origins permitted as post-login redirect targets. |
| `allowed_redirect_paths`    | comma list | no       | `["/"]`                     | Allow-list of paths permitted as post-login redirect targets. |

### HTTP and admin

| Key            | Type   | Required | Default | Description |
| -------------- | ------ | -------- | ------- | ----------- |
| `http_port`    | string | no       | `8080`  | Port the auth HTTP server listens on. |
| `admin_secret` | string | no       | —       | If set, guards `/admin` and `PATCH`/`POST /internal/session` via the `X-Admin-Secret` header. Empty disables those endpoints. |

### Optional integrations

| Key                      | Type       | Required | Default | Description |
| ------------------------ | ---------- | -------- | ------- | ----------- |
| `post_login_webhook_url` | string     | no       | —       | Optional webhook called after successful login. |
| `session_enrichment_api` | string     | no       | —       | Optional API used to enrich session data. |
| `cors_allowed_origins`   | comma list | no       | —       | Origins allowed for CORS. |
| `provider_plugin_id`     | string     | no       | —       | Selects an identity-provider plugin by ID or capability (e.g. `oidc`, `provider:oidc`). Empty uses the built-in OIDC provider configured above. |

> The runtime-only field `cookie_same_site` (the parsed `http.SameSite` value)
> carries the `json:"-"` tag and is **not** a config key — it is derived from
> `cookie_same_site` (the string above) during `Validate()`.

---

## accessgate-proxy

Source: `internal/proxy/config/config.go`. "Required" means `Validate()` returns
an error if the value is empty/invalid. "Default" is applied by `ApplyDefaults()`
when the value is empty/zero.

### Core

| Key                 | Type          | Required | Default              | Description |
| ------------------- | ------------- | -------- | -------------------- | ----------- |
| `upstream_url`      | string        | **yes**  | —                    | Upstream service URL the proxy forwards to. Scheme must be `http`/`https`. Validated against SSRF (see `allow_private_upstreams`). |
| `auth_url`          | string        | **yes**  | —                    | Base URL of `accessgate-auth` (session resolve, login flows). |
| `proxy_path_prefix` | string        | no       | `/graphql`           | Path prefix the proxy serves; a leading `/` is added if missing. |
| `require_auth`      | flexible bool | no       | `false`              | Whether requests must be authenticated. |
| `cookie_name`       | string        | no       | `__Host-ess_session` | Session cookie name (must match the auth service). |
| `http_port`         | string        | no       | `8081`               | Port the proxy HTTP server listens on. |

### Policy

| Key                     | Type             | Required | Default | Description |
| ----------------------- | ---------------- | -------- | ------- | ----------- |
| `policy_engine`         | string           | no       | `wasm`  | Policy backend: `wasm` or `rego`. Any other non-empty value is rejected by `Validate()`. |
| `policy_bundle_path`    | string           | no       | —       | Path to the policy bundle: a `.wasm` file (wasm engine) or `.rego` file (rego engine). |
| `policy_fallback_allow` | bool (nullable)  | no       | `false` | Behavior when no policy is loaded or evaluation fails: `true` = allow, `false` = deny (503). Defaults to deny; explicit `true` is required to allow unevaluated requests. |

### Plugins

| Key                     | Type                    | Required | Default | Description |
| ----------------------- | ----------------------- | -------- | ------- | ----------- |
| `pipeline_plugins`      | array of plugin entries | no       | —       | Pipeline plugin configs enabled at startup. Each entry has `id` (string), `type` (string), and `raw` (object: plugin-specific config). |
| `plugins_manifest_dir`  | string                  | no       | —       | Directory to discover plugin manifests (JSON). Empty disables filesystem discovery. |
| `plugins_manifest_strict` | bool                  | no       | `false` | When `true`, any manifest discovery or dependency-graph error fails startup (fail-closed). When `false`, such errors are logged clearly and startup proceeds. See [GUIDE-PLUGIN-AUTHORING.md](./GUIDE-PLUGIN-AUTHORING.md). |
| `plugins_manifest_public_key_path` | string       | no       | —       | Path to a PEM-encoded Ed25519 public key used to verify plugin manifest signatures. When set, every manifest must carry a valid signature (fail-closed). When empty, manifest signatures are not verified. |

### Security

| Key                       | Type   | Required | Default | Description |
| ------------------------- | ------ | -------- | ------- | ----------- |
| `admin_secret`            | string | no       | —       | If set, guards `/admin` via the `X-Admin-Secret` header. Empty disables the admin endpoint. |
| `bundle_public_key_path`  | string | no       | —       | Path to a PEM-encoded public key used to verify policy-bundle signatures. When empty, bundles load without integrity verification (a warning is logged). |
| `allow_private_upstreams` | bool   | no       | `false` | Disables SSRF IP-range validation for `upstream_url`. Set `true` **only** for local dev/test where the upstream is loopback/private. Never enable in production. |

When `allow_private_upstreams` is `false` (the default), `upstream_url` is
rejected if its host resolves to loopback, RFC-1918 private, link-local
(including the cloud metadata range `169.254.0.0/16`), or unique-local addresses.

### Header claim mapping

These keys map identity claims onto the upstream request headers.

| Key                                | Type   | Required | Default              | Description |
| ---------------------------------- | ------ | -------- | -------------------- | ----------- |
| `headers_user_id_claim`            | string | no       | `sub`                | Claim used for the user ID header. |
| `headers_email_claim`              | string | no       | `email`              | Claim used for the email header. |
| `headers_name_claim`               | string | no       | `name`               | Claim used for the display-name header. |
| `headers_preferred_username_claim` | string | no       | `preferred_username` | Claim used for the preferred-username header. |
| `headers_roles_claim`              | string | no       | `realm_access.roles` | Claim path used for the roles header. |
| `headers_groups_claim`             | string | no       | `groups`             | Claim used for the groups header. |
| `headers_tenant_id_claim`          | string | no       | —                    | Claim used for the tenant-ID header. No default; empty means unset. |
| `headers_admin_role`               | string | no       | `admin`              | Role value that designates an admin. |

---

## Example configs

Complete, schema-valid examples live in `configs/`:

- `configs/auth.example.json`, `configs/auth.example.yaml`
- `configs/proxy.example.json`, `configs/proxy.example.yaml`

The auth examples ship with empty `oidc_client_secret` / `cookie_signing_secret`;
supply real values via the `OIDC_CLIENT_SECRET` and `COOKIE_SIGNING_SECRET`
environment variables (env overrides file values). CI validates these examples
on every run; see the "Validate example configs" step in `.github/workflows/ci.yaml`.
