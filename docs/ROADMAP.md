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

## Now (current cycle)

- ✅ Consolidate org: archive AuthSentinel (canonical `accessgate/authsentinel`) and PolicyFront ecosystem repos; reconcile `LINEAGE.md` / `REPO-MAP.md`.
- ⬜ **Rename the Go module** `github.com/ArmanAvanesyan/accessgate` → `github.com/accessgate/accessgate` to match the repository. *(area/core-runtime)*
- 🚧 Repo hygiene: ignore scratch/tooling artifacts *(PR: repo-hygiene)*.
- 🚧 Add `pkg/token` unit tests (auth-critical; was 0% file coverage).
- 🚧 Add CI security scanning (`govulncheck` + CodeQL) and Dependabot.
- 🚧 Core docs: `ARCHITECTURE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `MIGRATION.md`, ADRs 0001–0004.

## Next

- ⬜ **Implement the GraphQL adapter** (`internal/graphql` is currently a stub) — parse operations and feed `GraphQLOperation` into policy input. *(area/proxy)*
- ⬜ **Implement the gRPC adapter** (`internal/grpc` is currently a stub) — extract service/method + metadata into policy input. *(area/proxy)*
- ⬜ **CI coverage gate** — enforce a minimum coverage threshold; expand integration coverage for `internal/auth/service` and `internal/proxy`. *(area/test)*
- ⬜ **Config validation in CI** — run `make validate-config` against the example configs; document every config key and keep schemas in sync. *(area/config)*
- ⬜ **WASM bundle signing, end-to-end** — document and test signed-bundle loading (`bundle_public_key_path`); add a signing how-to. *(area/policy)*
- ⬜ **Plugin system hardening** — make manifest discovery and dependency-graph build first-class (currently best-effort), with a plugin author guide. *(area/plugin)*
- ⬜ **SDK single source of truth** — declare and document the maintained home for each SDK; ensure none are sourced from archived PolicyFront repos. *(area/sdk)*
- ⬜ **Release process** — document tag → GoReleaser flow; add release notes conventions. *(area/packaging)*

## Later

- ⬜ **Supply-chain provenance** — SBOM generation and build provenance (e.g. SLSA) in the release workflow. *(area/packaging)*
- ⬜ **Multi-tenant policy context** — mature `TenantContext` handling and tenant-scoped obligations end-to-end. *(area/policy)*
- ⬜ **Policy hot-reload / bundle registry** — reload policy bundles without restart; optional remote bundle source. *(area/policy)*
- ⬜ **Session store options & HA** — document/extend Redis HA and alternative session backends. *(area/core-runtime)*
- ⬜ **Additional gateway integrations** — broaden beyond Caddy/Traefik/KrakenD as demand warrants. *(area/plugin)*
- ⬜ **Performance budgets** — benchmark the proxy hot path (principal resolve + policy eval) and set regression budgets. *(area/proxy)*

---

## How this roadmap is maintained

- New work enters as a GitHub issue with `area/*` + `priority/*` labels and lands on the **AccessGate Core Roadmap** project (Backlog → Ready → In Progress → In Review → Release Ready → Done).
- Cross-cutting consolidation/governance items use the **AccessGate Consolidation** project.
- Significant technical decisions are recorded as ADRs under [`docs/adr/`](adr/).
