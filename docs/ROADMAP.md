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

## Now (current cycle — v1.0 closure)

The binding constraint has shifted. Adoption friction is solved (images, compose,
Helm all shipped); what remains is **commitment risk at freeze**: once `v1.0.0` is
tagged, the config schema, proto wire format, and `pkg/**` Go API are SemVer-bound.
Cleanups are cheaper now than they will ever be again. This cycle closes the
**`v1.0`** milestone — cleanup → gate → freeze → tag, in that order (see umbrella
#86 for the full exit criteria).

- ⬜ **Pre-1.0 cleanups** — foot-gun config keys (`allow_private_upstreams`, `grpc_upstream_insecure`, nullable `policy_fallback_allow`), incidentally-exported `pkg` symbols, dead `session_enrichment_api` field, `headers_*_claim` naming. Must land **before** #100 locks the surface. *(area/core-runtime, P2, #101)*
- ⬜ **Go public-API diff gate** — apidiff/gorelease CI for `pkg/**`; mechanizes the SemVer promise after #101 cleans the surface. *(area/core-runtime, P2, #100)*
- ⬜ **Proto v1 field-numbering headroom review** — one-time pre-freeze pass; additive-only after the tag. *(area/core-runtime, P2, #104)*
- ⬜ **Security defaults, do-or-document** — CodeQL blocking decision; signature-required production profile; `cookie_secure` confirmation; Redis managed-endpoint-only HA stated as the supported 1.0 topology. *(area/core-runtime, P3, #102)*
- ⬜ **WASM benchmark fixture + perf baseline** — committed signed bundle; citable numbers for release notes (budgets-as-gate stays post-1.0, #50). *(area/policy, P2, #105)*
- ⬜ **Internal dead-code removal** — unused plugin states, unimplemented `IntegrationPlugin`. Parallel-safe. *(area/plugin, P3, #106)*
- ⬜ **Config-schema freeze** — the v1.0 config contract; flips `COMPATIBILITY.md` to "frozen"; records `AGENT_CONFIG` deprecation lifecycle. **Last content change before the tag.** *(area/core-runtime, P1, #103)*
- ⬜ **Cut `v1.0.0`** — tag; supply-chain pipeline green (SBOM + cosign + SLSA + GHCR multi-arch); close #86. *(milestone `v1.0`, #86)*

## Next (post-1.0 theme: **Operate with Confidence**)

The post-1.0 question is what converts a trial into a production deployment:
operators need to run it in HA, see it, and trust it won't regress.

- ⬜ **Redis Sentinel/Cluster support + client tuning knobs** — the top known gap in `SECURITY-POSTURE.md`; Sentinel/Cluster client paths, cross-slot `SCAN` rework, pool/timeout/retry config. Follow-on to #85. *(area/core-runtime, P2, #107)*
- ⬜ **Observability dashboards + alert examples** — Grafana dashboards/alerts for `accessgate_*` metrics; lowest-effort, highest-trust item now that metrics exist. *(area/observability, P3, #81)*
- ⬜ **Performance budgets as CI gate** — its stated preconditions (harness #82, published images) are now met; baseline from #105. *(area/proxy, P3, #50)*
- ⬜ **Supply-chain artifacts on `main` + changelog automation** — signatures/SBOM for untagged builds; GoReleaser release notes. *(area/packaging, P3, #108)*

## Later

Strategic bets; each lists its advance-signal.

- ⬜ **Multi-tenant policy context** — mature `TenantContext` + tenant-scoped obligations; advance on ≥3 adopter signals. *(area/policy, #46)*
- ⬜ **Alternative session backends** — beyond Redis; advance when an adopter can't run Redis at all (Redis HA #107 solves the proximate pain first). *(area/core-runtime, #48)*
- ⬜ **Remote policy bundle registry** — centralized multi-instance distribution; advance when a multi-instance fleet needs it (hot-reload + signing cover single-instance). *(area/policy, #84)*
- ⬜ **Additional gateway integrations** — beyond Caddy/Traefik/KrakenD; advance on a concrete adopter; includes disposition of the three archived PolicyFront gateway plugins. *(area/plugin, #49)*

---

## Shipped (2026-06)

- ✅ Org consolidation: AuthSentinel + PolicyFront repos archived; `LINEAGE.md`/`REPO-MAP.md` reconciled.
- ✅ Go module renamed → `github.com/accessgate/accessgate`.
- ✅ Repo hygiene; `pkg/token` unit tests; CI security scanning (`govulncheck` + CodeQL) + Dependabot.
- ✅ Core docs: `ARCHITECTURE`, `CONTRIBUTING`, `SECURITY`, `MIGRATION`, ADRs 0001–0004.
- ✅ GraphQL adapter (#70); gRPC adapter + proxy gRPC server (#74); CI coverage gate (#72); config validation + schema-drift CI + `CONFIG-KEYS.md` (#68/#66); WASM bundle signing — fail-closed Ed25519 + `bundle-sign` (#71); plugin discovery hardening + manifest signing (#73); SDK registry (#69); release docs (#67).
- ✅ **Adoption packaging cycle**: production container images + GHCR publish, distroless multi-arch (#77); docker-compose quickstart `deployments/docker/` (#78); README/RELEASING container docs (#79); image-tooling ADR 0005 (#83); perf benchmark harness + `BENCHMARKING.md` (#82).
- ✅ **"Next" horizon**: SBOM + cosign + SLSA provenance on `v*` tags (#45); transparent gRPC forwarding (#75); policy hot-reload, fail-closed last-good (#47); Helm chart `deploy/helm/accessgate` (#80); Redis HA guidance `REDIS-HA.md` (#85).
- ✅ **v1.0 audits**: `COMPATIBILITY.md` (#98) + `SECURITY-POSTURE.md` (#99) — spawned the closure-wave issues #100–#105.

---

## How this roadmap is maintained

- New work enters as a GitHub issue with `area/*` + `priority/*` labels and lands on the **AccessGate Core Roadmap** project (Backlog → Ready → In Progress → In Review → Release Ready → Done).
- Cross-cutting consolidation/governance items use the **AccessGate Consolidation** project.
- Significant technical decisions are recorded as ADRs under [`docs/adr/`](adr/).
- The **`v1.0`** GitHub milestone gathers the hardening bar (see umbrella #86); items bound for 1.0 are attached to it.
