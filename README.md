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

## Quickstart

Bring up a complete AccessGate stack locally with Docker Compose and watch a real
**allow (200) / deny (403)** decision flow through the proxy — no external IdP and
no cloud account, in about five minutes.

The stack is `accessgate-proxy` + `accessgate-auth` + an in-repo mock OIDC issuer
(`mockidp`) + Redis + a sample [httpbin] upstream, defined in
[`deployments/docker/`](deployments/docker/). Images are built from the committed
multi-stage Dockerfiles in [`build/docker/`](build/docker/) (distroless, non-root).

```bash
git clone https://github.com/accessgate/accessgate.git
cd accessgate/deployments/docker
cp .env.example .env          # the only required value is COOKIE_SIGNING_SECRET
docker compose up -d --build  # first build compiles the Go services (~1–2 min)
```

Once the services report `(healthy)` (`docker compose ps`), exercise the sample
policy, which **allows `GET /anything/allow`** and **denies everything else**
(deny-by-default):

```bash
# ALLOW → 200, proxied to the upstream
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/allow
# 200

# DENY → 403, short-circuited by the policy (never reaches the upstream)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/deny
# 403
```

Tear it down with `docker compose down` (add `-v` to drop the ephemeral Redis data).

For the full walkthrough — editing the policy, requiring authentication, logging in
through the mock IdP, and configuration notes — see the
[Docker quickstart guide](deployments/docker/README.md). `make e2e-docker` runs the
same stack end-to-end as a smoke test.

### Published images

Tagged releases (`v*`) publish multi-arch (`linux/amd64`, `linux/arm64`) images to
the GitHub Container Registry, so you can run AccessGate without building from source:

```bash
docker pull ghcr.io/accessgate/accessgate-proxy:<tag>
docker pull ghcr.io/accessgate/accessgate-auth:<tag>
```

See [docs/RELEASING.md](docs/RELEASING.md) for image names, tags, and the publish
flow.

[httpbin]: https://httpbin.org/

---

## Repository structure

This repository contains the core runtime and shared contracts:

- `cmd/` — binaries and CLI entrypoints (`accessgate-auth`, `accessgate-proxy`, tools)
- `internal/` — internal runtime implementation
- `pkg/` — reusable public Go packages (e.g. `pkg/auth` API types)
- `proto/` — protobuf API contracts
- `test/` — contract, integration, and e2e-oriented tests
- `.github/workflows/` — CI/release workflows

First-party container images and the local Docker Compose stack live in this repo
(`build/docker/`, `deployments/docker/`). Related ecosystem repositories may include
Helm charts, gateway plugins, and language SDKs (see your organization’s documentation).

---

## Build from source

The [Quickstart](#quickstart) above is the fastest path to a running stack. Build
from source when you want to develop against the runtime or run the binaries
directly.

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

For production, follow the supported **[Production profile](docs/SECURITY-POSTURE.md#5-production-profile-supported-10-stance)**
(signed policy bundles + plugin manifests required, `cookie_secure: true`,
fail-closed policy fallback, managed-endpoint Redis HA). In summary:

- Set IdP issuer/client credentials via secure secret management
- Configure cookie/session settings for your domain and TLS posture (`cookie_secure: true`)
- Set explicit upstream allowlists and timeout limits
- Require signed policy bundles (`bundle_public_key_path`) and signed plugin
  manifests (`plugins_manifest_public_key_path`)
- Keep `policy_fallback_allow` unset/false (fail closed)
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

- Release metadata is defined in `.goreleaser.yaml`: OS/arch binary archives
  (`accessgate-auth`, `accessgate-proxy`) plus multi-arch container images
  published to GHCR on `v*` tags. See [docs/RELEASING.md](docs/RELEASING.md).

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
See [SECURITY.md](SECURITY.md) for the disclosure process and
[docs/SECURITY-POSTURE.md](docs/SECURITY-POSTURE.md) for the code-grounded v1.0
posture, including the supported
[Production profile](docs/SECURITY-POSTURE.md#5-production-profile-supported-10-stance).

Recommended hardening:

- Use HTTPS everywhere
- Restrict callback/redirect URLs
- Enforce strict session cookie settings (`cookie_secure: true`)
- Require signed policy bundles and signed plugin manifests in production
- Monitor auth and policy decision telemetry

---

## License

Apache-2.0 (or your selected project license).

---

## Status

AccessGate is under active development. APIs and extension contracts may evolve between minor releases.
