# AccessGate

AccessGate is an open-source, policy-driven authentication and authorization runtime for modern applications and API gateways.

It provides:

- **accessgate-auth** — OIDC login, callback, refresh, logout, and session endpoints
- **accessgate-proxy** — request-time policy enforcement and upstream forwarding
- **AccessGate Policy** (embedded in the proxy) — consistent allow/deny decisions (Rego/WASM)
- **Gateway integrations** for Caddy, Traefik, and KrakenD
- **SDK foundations** for web and server-side integrations

---

## Why AccessGate

AccessGate helps teams centralize auth enforcement at the edge while keeping application code simple.

- Enforce auth and policy decisions consistently across services
- Integrate with existing OAuth/OIDC identity providers
- Add gateway-native protections without rewriting every app
- Keep policies auditable and testable

---

## Repository structure

This repository contains the core runtime and shared contracts:

- `cmd/` — binaries and CLI entrypoints (`accessgate-auth`, `accessgate-proxy`, tools)
- `internal/` — internal runtime implementation
- `pkg/` — reusable public Go packages (e.g. `pkg/auth` API types)
- `proto/` — protobuf API contracts
- `test/` — contract, integration, and e2e-oriented tests
- `.github/workflows/` — CI/release workflows

Related ecosystem repositories may include Helm charts, Docker image builds, gateway plugins, and language SDKs (see your organization’s documentation).

---

## Quick start

### Prerequisites

- Go (latest stable)
- Make
- Docker (optional, for local stack/e2e)

### Build

```bash
go build -o accessgate-auth ./cmd/accessgate-auth
go build -o accessgate-proxy ./cmd/accessgate-proxy
```

### Run locally (example)

Set runtime config via environment variables (or `CONFIG_PATH` with your own config file) and run:

```bash
./accessgate-auth
./accessgate-proxy
```

Use `AUTH_CONFIG` / `PROXY_CONFIG` (or `CONFIG_PATH`) for config file paths. The proxy uses `auth_url` for the accessgate-auth base URL.

---

## Core concepts

- **accessgate-auth**: user-facing auth lifecycle endpoints (`/login`, `/callback`, `/refresh`, `/logout`, `/session`)
- **accessgate-proxy**: validates session/token context and enforces policy before forwarding upstream
- **AccessGate Policy**: evaluates request and identity context to produce allow/deny decisions (embedded in the proxy)
- **Plugins/integrations**: embed AccessGate behavior into supported gateways

---

## Configuration

For production:

- Set IdP issuer/client credentials via secure secret management
- Configure cookie/session settings for your domain and TLS posture
- Set explicit upstream allowlists and timeout limits
- Enable observability (metrics/tracing/log correlation)

---

## Development

### Run tests

```bash
go test ./...
```

### Lint and quality checks

Use the CI workflow as the source of truth for required checks before merge.

---

## Release

- Binary release metadata is defined in `.goreleaser.yaml` (artifacts `accessgate-auth`, `accessgate-proxy`)

---

## Migration from PolicyFront naming

If you are upgrading from older **PolicyFront**-named artifacts and telemetry:

- Go module path is `github.com/accessgate/accessgate` (update imports accordingly).
- Binaries are **`accessgate-auth`** and **`accessgate-proxy`** (not `policyfront-agent` / `policyfront-proxy`).
- Prometheus metric names use the `accessgate_*` prefix (for example `accessgate_auth_decisions_total` replaces `policyfront_auth_decisions_total`). Update dashboards and alerts.
- Default OpenTelemetry service name when `OTEL_SERVICE_NAME` is unset is **`accessgate`**.
- Rego policies must use `package accessgate` and the rule queried is **`data.accessgate.decision`** (previously `data.policyfront.decision`).
- Protobuf packages live under `accessgate/*` (for example `accessgate.auth.v1`, `accessgate.sdk.v1`).

---

## Security

Please report vulnerabilities privately via your security contact channel before public disclosure.

Recommended hardening:

- Use HTTPS everywhere
- Restrict callback/redirect URLs
- Enforce strict session cookie settings
- Monitor auth and policy decision telemetry

---

## License

Apache-2.0 (or your selected project license).

---

## Status

AccessGate is under active development. APIs and extension contracts may evolve between minor releases.
