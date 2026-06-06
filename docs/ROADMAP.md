# AccessGate Roadmap

This roadmap captures the direction for the AccessGate core runtime and its
ecosystem. It is organized by **theme** and **horizon** (Now / Next / Later).
Horizons express sequencing and confidence, not hard dates. Items are tracked as
GitHub issues on the **AccessGate Core Roadmap** project and labeled by `area/*`
and `priority/*`.

Status legend: ✅ done · 🚧 in progress · ⬜ planned

## Themes

1. **Core runtime completeness** — finish partial subsystems; make the auth/proxy/policy paths fully featured.
2. **Security & supply chain** — fail-closed defaults, scanning, signed artifacts, provenance.
3. **Quality & testing** — coverage, contract/integration/e2e depth, CI gates.
4. **Documentation & developer experience** — architecture, ADRs, migration, contributor onboarding.
5. **Ecosystem & consolidation** — single sources of truth for SDKs/plugins/packaging; finish the AuthSentinel/PolicyFront → AccessGate consolidation.
6. **Observability & operations** — metrics/tracing maturity, HA guidance, release process.

---

## Now (current cycle — adoption packaging)

The binding constraint is adoption friction: AccessGate is OSS infrastructure with no
`docker run` / `docker compose up` path today. This cycle makes trial-to-running take
minutes, not hours. Tracked toward the **`v1.0`** milestone.

- ⬜ **Production container images + GHCR publish workflow** — distroless, multi-arch (amd64/arm64), non-root images for `accessgate-auth`/`accessgate-proxy`, published to GHCR on release. In-repo. *(area/packaging, P1, #77)*
- ⬜ **docker-compose quickstart stack** — `deployments/docker/`: auth + proxy + redis + sample upstream/OIDC/policy; `docker compose up` → allow/deny in < 5 min (also fixes the dangling `make e2e-docker`). *(area/packaging, P1, #78)*
- ⬜ **README quickstart + RELEASING container docs**. *(area/docs, P1, #79)*
- ⬜ **ADR: container image tooling** — ko vs GoReleaser `dockers:` (blocks #77). *(area/packaging, P1, #83)*
- ⬜ **Perf benchmark harness (spike)** — repeatable hot-path bench so 1.0 can cite numbers. *(area/proxy, P2, #82)*

## Next

- ⬜ **SBOM + provenance + image signing** — cosign + syft (SBOM) + SLSA provenance, in the publish workflow. *(area/packaging, P2, #45)*
- ⬜ **Transparent gRPC forwarding** — authorize *and* forward the gRPC call to the upstream (raw-codec director); completes PR #74. *(area/proxy, P2, #75)*
- ⬜ **Policy hot-reload (local file watch)** — reload bundles without restart, fail-closed during reload (remote registry split to Later). *(area/policy, P2, #47)*
- ⬜ **Helm chart (in-repo `deploy/helm/`)** — for Kubernetes adopters once compose proves the value. *(area/packaging, P2, #80)*
- ⬜ **Session HA guidance doc (Redis)** — operational topologies for sessions/PKCE/refresh-lock. *(area/core-runtime, P3, #85)*
- ⬜ **v1.0 hardening (umbrella)** — config-schema freeze, breaking-change audit, perf budgets, security pass. *(milestone `v1.0`, #86)*

## Later

- ⬜ **Multi-tenant policy context** — mature `TenantContext` + tenant-scoped obligations; advance on ≥3 adopter signals. *(area/policy, #46)*
- ⬜ **Alternative session backends** — beyond Redis; advance when an adopter can't run Redis. *(area/core-runtime, #48)*
- ⬜ **Remote policy bundle registry** — centralized multi-instance policy distribution. *(area/policy, #84)*
- ⬜ **Additional gateway integrations** — beyond Caddy/Traefik/KrakenD, demand-driven. *(area/plugin, #49)*
- ⬜ **Performance budgets as CI gate** — after the harness (#82) and a published image have real usage. *(area/proxy, #50)*
- ⬜ **Observability dashboards + alert examples** — Grafana dashboards/alerts for `accessgate_*` metrics. *(area/observability, #81)*

---

## Shipped (2026-06)

- ✅ Org consolidation: AuthSentinel + PolicyFront repos archived; `LINEAGE.md`/`REPO-MAP.md` reconciled.
- ✅ Go module renamed → `github.com/accessgate/accessgate`.
- ✅ Repo hygiene; `pkg/token` unit tests; CI security scanning (`govulncheck` + CodeQL) + Dependabot.
- ✅ Core docs: `ARCHITECTURE`, `CONTRIBUTING`, `SECURITY`, `MIGRATION`, ADRs 0001–0004.
- ✅ GraphQL adapter (#70); gRPC adapter + proxy gRPC server (#74); CI coverage gate (#72); config validation + schema-drift CI + `CONFIG-KEYS.md` (#68/#66); WASM bundle signing — fail-closed Ed25519 + `bundle-sign` (#71); plugin discovery hardening + manifest signing (#73); SDK registry (#69); release docs (#67).

---

## How this roadmap is maintained

- New work enters as a GitHub issue with `area/*` + `priority/*` labels and lands on the **AccessGate Core Roadmap** project (Backlog → Ready → In Progress → In Review → Release Ready → Done).
- Cross-cutting consolidation/governance items use the **AccessGate Consolidation** project.
- Significant technical decisions are recorded as ADRs under [`docs/adr/`](adr/).
- The **`v1.0`** GitHub milestone gathers the hardening bar (see umbrella #86); items bound for 1.0 are attached to it.
