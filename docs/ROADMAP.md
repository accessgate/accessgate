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
- ✅ **Rename the Go module** `github.com/ArmanAvanesyan/accessgate` → `github.com/accessgate/accessgate` to match the repository. *(area/core-runtime)*
- ✅ Repo hygiene: ignore scratch/tooling artifacts.
- ✅ Add `pkg/token` unit tests (auth-critical; was 0% file coverage).
- ✅ Add CI security scanning (`govulncheck` + CodeQL) and Dependabot.
- ✅ Core docs: `ARCHITECTURE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `MIGRATION.md`, ADRs 0001–0004.

## Next — completed (2026-06)

- ✅ **GraphQL adapter** — operation extraction (raw + JSON) wired into authz. *(area/proxy, PR #70)*
- ✅ **gRPC adapter + proxy gRPC server** — `ExtractMethod`, authz interceptors, config-gated gRPC listener (terminate-and-authorize; transparent forwarding tracked in #75). *(area/proxy, PR #74)*
- ✅ **CI coverage gate** — 40% threshold + expanded proxy/auth integration tests. *(PR #72)*
- ✅ **Config validation in CI** — `make validate-config` on examples + schema-drift check; `docs/CONFIG-KEYS.md`; cross-platform `validateconfig` fix. *(PR #68, #66)*
- ✅ **WASM bundle signing, end-to-end** — fail-closed Ed25519 verification + `bundle-sign` CLI + `docs/GUIDE-POLICY-SIGNING.md`. *(area/policy, PR #71)*
- ✅ **Plugin system hardening** — strict mode, manifest validation, Ed25519 manifest signing, `docs/GUIDE-PLUGIN-AUTHORING.md`. *(area/plugin, PR #73)*
- ✅ **SDK single source of truth** — `docs/SDK-REGISTRY.md`. *(area/sdk, PR #69)*
- ✅ **Release process** — `docs/RELEASING.md`. *(area/packaging, PR #67)*

## Later

- ⬜ **Transparent gRPC forwarding** — proxy the authorized gRPC call to the upstream backend (raw-codec director); builds on the terminate-and-authorize server from PR #74. *(area/proxy, #75)*
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
