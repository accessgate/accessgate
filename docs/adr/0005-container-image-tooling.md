# ADR-0005: Container image build and publish via checked-in Dockerfiles and GoReleaser

- **Status**: Accepted
- **Date**: 2026-06-07

## Context

AccessGate ships two binaries — `accessgate-auth` and `accessgate-proxy` (ADR-0002) — and
today the release pipeline (`.goreleaser.yaml`, the `release` job in
`.github/workflows/ci.yaml`) builds and publishes only OS/arch archives to GitHub Releases on
a `v*` tag. There is no container image build yet: the comment in `.goreleaser.yaml` ("Docker
images via separate workflow") and the [RELEASING](../RELEASING.md) "Not produced today" note
are both aspirational. Roadmap issue #83 asks us to choose the tooling that produces and
publishes OCI images for the two binaries.

The codebase makes this straightforward: Go 1.26.4, pure-Go (no cgo) with `proto/gen`
committed, so a plain `go build ./cmd/...` works; the binary build matrix already covers
`linux/{amd64,arm64}`; and both services expose `GET /healthz`
(`internal/{auth,proxy}/httpserver/server.go`). We weighed two options:

- **A) Checked-in multi-stage Dockerfiles + GoReleaser `dockers:`/`docker_manifests:`** —
  real, reviewable `Dockerfile`s in the repo, wired into the existing GoReleaser release job
  that already runs on `v*` tags.
- **B) [`ko`](https://ko.build)** — no Dockerfile, distroless-by-default, builds images
  straight from Go with minimal config.

`ko` is genuinely attractive on ergonomics (no Dockerfile to maintain, reproducible,
distroless and non-root by default, native multi-arch). However, the project owner stated a
hard requirement: **users must get ready-to-use Dockerfiles they can read and modify in the
repo.** `ko` produces no Dockerfile by design, so it cannot satisfy that requirement — that is
the deciding constraint, not a marginal preference. With `ko` excluded, Option A also keeps
image builds inside the one release path we already operate, rather than adding a second tool.

## Decision

**We will build and publish container images using checked-in multi-stage Dockerfiles driven
by GoReleaser**, extending the existing release pipeline rather than introducing a new tool.

Concrete shape:

- **Dockerfiles in the repo**, one per binary (e.g. `build/docker/Dockerfile.auth`,
  `build/docker/Dockerfile.proxy`), authored as **multi-stage** builds: a `golang:1.26`
  builder stage compiling a static binary (`CGO_ENABLED=0`), and a minimal final stage on
  **`gcr.io/distroless/static`** (the static, libc-free distroless base — appropriate because
  the binaries are pure-Go). These are real, reviewable, customizable files — the stated
  requirement.
- **Multi-arch** `linux/amd64` and `linux/arm64`, matching the existing binary matrix and
  joined into a single multi-arch manifest per image via GoReleaser `docker_manifests:`.
- **Non-root**: images run as a non-root user (distroless `nonroot`), no shell, minimal
  surface.
- **`HEALTHCHECK`** targeting each service's existing `GET /healthz`.
- **Registry**: GitHub Container Registry, `ghcr.io/accessgate/accessgate-auth` and
  `ghcr.io/accessgate/accessgate-proxy`.
- **Tag-driven publish**: images are built and pushed by the GoReleaser `release` job on a
  `v*` tag (same trigger as today's archives), authenticating to GHCR with the workflow's
  token; tags follow the release version plus a moving `latest`.
- **Image signing / SBOM / provenance** were deferred to #45 — **now implemented**:
  the release pipeline produces SBOMs, keyless cosign signatures (checksums file and
  images), and SLSA build provenance. See [RELEASING](../RELEASING.md#supply-chain-artifacts-and-verification).

## Consequences

- Operators and downstream consumers get **actual Dockerfiles** to read, fork, and customize,
  satisfying the owner's hard requirement; the base image, user, and build flags are all
  visible and editable in-tree.
- Image builds reuse the **single existing release path** (`v*` tag → GoReleaser), so there is
  no second publish mechanism to learn, secure, or keep in sync. RELEASING docs and the
  `.goreleaser.yaml` "separate workflow" comment get updated to describe reality (follow-up,
  tracked alongside #83 / docs issue #79).
- `gcr.io/distroless/static` keeps images small and low-surface (non-root, no shell/package
  manager), which suits the proxy's hot-path, minimal-attack-surface posture (ADR-0002).
- **Costs / trade-offs vs. the rejected `ko` option:**
  - We now **own and maintain the Dockerfiles** — base-image bumps (e.g. distroless digest
    pinning, Go builder version) are manual and must track the `go.mod` Go version. `ko` would
    have removed this upkeep and handled base/SBOM/multi-arch automatically.
  - GoReleaser's Docker support **requires a working buildx/QEMU setup in CI** for cross-arch
    builds; the release job gains Docker/buildx + GHCR-login steps and `packages: write`
    permission. `ko` builds multi-arch without an external Docker daemon.
  - We must **pin and periodically update** the distroless and builder base images to avoid
    drift and stale CVEs; that hygiene is a standing obligation that `ko`'s managed bases would
    have largely absorbed.
- **Follow-up**: implementing the Dockerfiles + GoReleaser `dockers:`/`docker_manifests:`
  wiring and the GHCR-publish CI steps is tracked under the container-images work item (#77);
  image signing/SBOM/provenance (#45) has since been implemented on top of this pipeline
  (keyless cosign + syft SBOMs + SLSA provenance, GitHub OIDC).
