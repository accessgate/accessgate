# AccessGate v1.0 Security Posture

> A grounded summary of AccessGate's security posture for the v1.0 line, audited
> against the actual code and CI in this repository (`github.com/accessgate/accessgate`).
> Every claim below cites the file that implements it. For the disclosure process
> and operational hardening checklist, see [SECURITY.md](../SECURITY.md).
>
> Roadmap umbrella: **#86** (v1.0 hardening). This document is descriptive — it
> records what the code does today and flags real gaps as follow-ups; it does not
> promise unimplemented work.

---

## 1. Supply chain & CI scanning

**Static analysis and vulnerability scanning** run on every push/PR to `main`
(and weekly via cron) in `.github/workflows/security.yml`:

- **`govulncheck` (blocking).** `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
  runs as a required step; a new finding fails the build
  (`.github/workflows/security.yml`, `govulncheck` job). The toolchain is pinned
  via `go.mod` so the scan is reproducible.
- **CodeQL (blocking on error-level findings).** The `codeql` job analyzes Go
  and uploads results to the code-scanning dashboard, **and** gates the build:
  the analysis writes its SARIF locally (`analyze` step `output:`) and a
  follow-up step fails the run if any result's effective level is `error`
  (`.github/workflows/security.yml`, `codeql` job, "Gate on error-level CodeQL
  findings"). Warning- and note-level findings remain **informational** — they
  surface on the dashboard but do not block PRs, to avoid gating on
  lower-confidence or stylistic results. The gate is green on `main` as of this
  change (the lone error-level finding, `go/bad-redirect-check` in
  `internal/auth/service/redirect.go`, was fixed by rejecting protocol-relative
  `//`/`/\` redirect targets).
- **Weekly rescan.** A `schedule: cron "0 7 * * 1"` re-runs the scans to catch
  newly disclosed CVEs in already-pinned dependencies between code changes.

**Dependency updates** are automated via `.github/dependabot.yml`: weekly PRs for
Go modules (`gomod`, root) and GitHub Actions (`github-actions`), labelled and
scoped.

**Release supply-chain hardening (issue #45)** ships on every `v*` tag, configured
in `.goreleaser.yaml` and driven by the `release` job in
`.github/workflows/ci.yaml`. The release job runs with least privilege plus the
elevated scopes signing/attestation require: `contents: write`, `packages: write`,
`id-token: write` (OIDC for keyless signing), and `attestations: write`.

| Artifact | Tooling | How it's enforced |
| --- | --- | --- |
| **SBOM** (SPDX-JSON, one per archive) | `syft` via GoReleaser `sboms:` | `.goreleaser.yaml` `sboms.archive-sbom`; `anchore/sbom-action/download-syft` installs syft (`ci.yaml`) |
| **Checksum signature** (keyless cosign) | `cosign sign-blob` | `.goreleaser.yaml` `signs.checksum-keyless` → `checksums.txt.sig` + `.pem` |
| **Container image signatures** (keyless cosign, by digest) | `cosign sign` | `.goreleaser.yaml` `docker_signs.image-keyless`; stored as OCI artifacts in GHCR |
| **SLSA build provenance** (binaries + image digests) | `actions/attest-build-provenance@v2` | `ci.yaml` release steps; image attestations pushed to registry by resolved digest |

All signing is **keyless** (Sigstore/Fulcio + Rekor via GitHub Actions OIDC) — there
are **no private keys to manage or rotate**.

**Verification commands** (full walkthrough in [docs/RELEASING.md](RELEASING.md#supply-chain-artifacts-and-verification)):

```bash
ISSUER='https://token.actions.githubusercontent.com'

# Checksums (and thus archives):
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity 'https://github.com/accessgate/accessgate/.github/workflows/ci.yaml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer "$ISSUER" checksums.txt

# Container image:
cosign verify \
  --certificate-identity-regexp '^https://github.com/accessgate/accessgate/\.github/workflows/ci\.yaml@refs/tags/v.*$' \
  --certificate-oidc-issuer "$ISSUER" ghcr.io/accessgate/accessgate-proxy:X.Y.Z

# Build provenance:
gh attestation verify oci://ghcr.io/accessgate/accessgate-proxy:X.Y.Z --repo accessgate/accessgate
```

Images are built from checked-in multi-stage Dockerfiles onto
`gcr.io/distroless/static:nonroot` — non-root, no shell (ADR-0005,
`build/docker/Dockerfile.{auth,proxy}`). PR CI builds both images (no push) so the
Dockerfiles are exercised before release.

## 2. Policy & plugin integrity (fail-closed)

**WASM bundle signature verification (Ed25519).** When `bundle_public_key_path` is
configured, the proxy verifies each bundle's **detached Ed25519 signature**
(`<bundle>.wasm.sig`) over the raw bundle bytes **before** the module is compiled
or instantiated (`internal/policy/bundle.go` `LoadBundle`,
`internal/policy/signature.go`). The guarantee is **fail-closed**: a missing `.sig`
(`ErrSignatureMissing`), an unparseable key, a malformed/wrong-length signature, or
a signature that does not validate **all** abort the load — the unverified bundle is
never compiled (`internal/policy/signature.go` `verifyBundleFile`,
`verifyBundleSignature`). Hot-reload re-verifies on every reload and retains the
last-good policy on failure rather than entering a deny-all state
(`internal/proxy/config/config.go`, `PolicyReloadEnabled`). Signatures are produced
offline by the `bundle-sign` CLI (`cmd/bundle-sign`). See
[docs/GUIDE-POLICY-SIGNING.md](GUIDE-POLICY-SIGNING.md).

> Caveat: if `bundle_public_key_path` is **empty**, verification is skipped and a
> warning is logged (`internal/policy/bundle.go` `NewBundleLoader`). Signing is
> opt-in; configure the key in production.

**Plugin manifest signing (Ed25519) + strict discovery.** Plugin manifests may
carry an inline Ed25519 signature over the canonical JSON of the manifest with its
`signature` field cleared (`internal/plugin/signature.go` `Ed25519Verifier.Verify`,
`signingPayload`). When `plugins_manifest_public_key_path` is set, **every**
discovered manifest must carry a valid signature or discovery fails — a missing
signature, unsupported algorithm, malformed value, or invalid signature all return
an error and the manifest is **not registered** (`internal/plugin/discovery.go`
`discoverSingle`). `plugins_manifest_strict: true` makes any discovery or
dependency-graph error fail startup (fail-closed); the default is non-strict for
backward compatibility (`internal/proxy/config/config.go`). See
[docs/GUIDE-PLUGIN-AUTHORING.md](GUIDE-PLUGIN-AUTHORING.md).

## 3. Request-path defenses

- **SSRF protection (HTTP + gRPC upstreams).** Both the HTTP `upstream_url` and the
  gRPC `grpc_upstream_addr` are validated at startup against a shared blocked-CIDR
  set covering loopback, RFC-1918 private ranges, link-local (incl. the
  `169.254.0.0/16` cloud-metadata range), IPv6 ULA/link-local, and `0.0.0.0/8`
  (`internal/proxy/config/config.go` `validateUpstreamSSRF`,
  `validateGRPCUpstreamSSRF`; mirrored in `internal/authz/http.go` `blockedCIDRs`).
  Hostnames are resolved and **every** resolved IP is checked. Only `http`/`https`
  schemes are allowed. The escape hatch `allow_private_upstreams: true` is for local
  dev only and disables the IP-range check (`Config.Validate`).
- **Header-injection (CRLF) stripping.** Obligation-derived response headers have
  CR (`\r`) and LF (`\n`) stripped from both the header **name** and **value**
  before they are set, preventing header/response splitting
  (`internal/authz/engine.go`, "Strip CRLF to prevent header injection").
- **Policy fail-closed default.** `policy_fallback_allow` defaults to **deny** — when
  no policy is loaded or evaluation fails, the request is denied with `503` unless an
  operator explicitly opts into allow. `PolicyFallbackAllow` is fail-closed by its zero
  value: an unset/empty key is equivalent to `false` (deny)
  (`internal/proxy/config/config.go`; `internal/authz/engine.go` defaults an unset
  decision to deny/`503`).
- **Request body cap.** Inbound bodies are capped at 32 MB via
  `http.MaxBytesReader` (`internal/authz/http.go` `RequestFromHTTP`).
- **Session/cookie hardening.** Session cookies carry only an opaque session ID,
  signed with **HMAC-SHA256** and supporting key rotation (`pkg/cookie/signed.go`
  `SignedManager`). The default cookie name uses the **`__Host-` prefix**
  (`__Host-ess_session`, `internal/auth/config/config.go`,
  `internal/proxy/config/config.go`), and the auth server enforces the prefix's
  invariants — `Secure=true` and no `Domain` — whenever the name starts with
  `__Host-` (`internal/auth/httpserver/server.go` `cookieOpts`). Cookies are always
  `HttpOnly`, with configurable `SameSite` (default `Lax`) and `Secure`
  (`internal/auth/service/service.go`).

## 4. Secrets handling

- **No secrets in the repo.** The OIDC client secret (`oidc_client_secret`), cookie
  signing secret (`cookie_signing_secret`), and admin secret (`admin_secret`) are
  provided via environment variables / files (go-config file+env loader), never
  committed. Example configs ship with empty secrets injected at CI time via env
  (`.github/workflows/ci.yaml` "Validate example configs").
- **Placeholder rejection.** `Config.Validate` refuses to start if it detects the
  known placeholder values (`oidc_client_secret == "your-client-secret"` or
  `cookie_signing_secret == "CHANGE-ME-in-production"`) and requires the cookie
  signing secret to be set at all (`internal/auth/config/config.go` `Validate`).
- **Kubernetes.** The Helm chart sources secrets from a `Secret` and injects them
  via `secretKeyRef` rather than plaintext env in the manifest
  (`deploy/helm/accessgate/templates/secret.yaml`, `auth-deployment.yaml`,
  `proxy-deployment.yaml`).

## 5. Production profile (supported 1.0 stance)

Several defenses above are **opt-in** in the code for backward compatibility, but
are **required** for a supported v1.0 production deployment. "Production profile"
is the configuration AccessGate is hardened and supported against; running outside
it is possible but unsupported and at the operator's risk. Treat this section as
the deployment contract — the install guides, Helm values, and Docker compose
files reference it.

| Setting | Required production stance | Why |
| --- | --- | --- |
| `bundle_public_key_path` | **Set** (WASM policy bundle signing) | Without it the proxy loads **unverified** bundles; only a configured key engages fail-closed Ed25519 verification (§2). |
| `plugins_manifest_public_key_path` | **Set** (plugin manifest signing) | Without it discovered plugin manifests are **not** signature-checked; with it every manifest must carry a valid Ed25519 signature or discovery fails (§2). Pair with `plugins_manifest_strict: true`. |
| `cookie_secure` | **`true`** | Forces cookies over HTTPS only. The `__Host-` prefix default enforces `Secure` **for prefixed names only** — a custom (non-`__Host-`) cookie name does **not** get this for free, so set it explicitly (§3). |
| `policy_fallback_allow` | **unset / `false`** | Keeps the proxy fail-closed (deny + `503`) when no policy is loaded or evaluation fails (§3). Setting it to `true` is a fail-open posture and is unsupported in production. |
| `allow_private_upstreams` | **unset / `false`** unless explicitly justified | Disables the SSRF IP-range check; intended for local dev. Enable only with a documented justification and compensating network controls (§3). |
| `grpc_upstream_insecure` | **unset / `false`** unless explicitly justified | Disables TLS to the gRPC upstream. Enable only with a documented justification and a trusted network path. |

**Redis topology.** The supported 1.0 HA topology is a **managed Redis endpoint
that presents a single stable address and fails over internally** — the client is
single-endpoint only and is not Sentinel/Cluster-aware
(`internal/redis/redis.go`). Native Sentinel/Cluster support is a tracked code
follow-up (**#107**); see [docs/REDIS-HA.md](REDIS-HA.md) for the supported
operational pattern.

These requirements are also reflected, where trivially doable, in the deployment
assets ([deployments/docker](../deployments/docker),
[deploy/helm](../deploy/helm/accessgate)) and summarized in
[SECURITY.md](../SECURITY.md#operational-hardening-recommendations) and the
[README](../README.md).

## 6. Known gaps & hardening backlog

Being honest about what is **not** yet covered:

- **Redis client is single-endpoint only.** `internal/redis/redis.go` uses a plain
  `redis.NewClient` — it is **not** Sentinel-aware and **not** Cluster-aware. For
  1.0 this is **resolved as a documented stance**: the supported HA topology is a
  managed Redis that presents one stable endpoint and fails over internally (see
  the [Production profile](#5-production-profile-supported-10-stance) and
  [docs/REDIS-HA.md](REDIS-HA.md)). Native Sentinel/Cluster support is a tracked
  code follow-up (**#107**).
- **CodeQL gates on error-level findings.** Resolved: the `codeql` job fails the
  build on any `error`-level result while keeping warning/note findings
  informational (`.github/workflows/security.yml`; see §1). The gate is green on
  `main`.
- **No Go public-API diff gate.** CI gates proto breaking changes (`make
  proto-breaking`) and config-schema drift, but there is no automated check for
  breaking changes to exported Go packages — relevant pre-1.0 where the public API
  is still settling (`docs/RELEASING.md`). Tracked as a follow-up; not in scope
  for the 1.0 security-defaults wave.
- **Image signing/SBOM/provenance only run on tags.** All `#45` supply-chain
  artifacts are produced by the tag-gated `release` job; untagged `main` builds get
  no signatures or attestations (`.github/workflows/ci.yaml`).
- **Policy/plugin signing is opt-in *in code*, required *in production*.** Bundle
  and manifest verification only engage when the respective public-key paths are
  configured; the unsigned path remains for backward compatibility. For 1.0 this is
  **resolved as a documented stance** — configuring both keys is **required** in
  the supported [Production profile](#5-production-profile-supported-10-stance).
- **Rotate any embedded credentials.** If a token or secret is ever exposed — e.g.
  a PAT embedded in a git remote URL, or any committed credential — revoke and
  rotate it immediately, then scrub it from configs and remotes (see
  [SECURITY.md](../SECURITY.md#credential-hygiene)).

---

## v1.0 security checklist

**Done ✓**

- [x] Blocking `govulncheck` on every push/PR + weekly cron (`security.yml`)
- [x] CodeQL Go analysis to the code-scanning dashboard, **blocking on error-level findings** (`security.yml`)
- [x] Dependabot for Go modules and GitHub Actions (`dependabot.yml`)
- [x] Keyless cosign signatures (checksums + images), syft SBOMs, SLSA provenance on `v*` tags (`.goreleaser.yaml`, `ci.yaml`)
- [x] Documented verification commands (`docs/RELEASING.md`)
- [x] Distroless, non-root, no-shell container images (ADR-0005)
- [x] Fail-closed Ed25519 WASM bundle signature verification before compile (`internal/policy`)
- [x] Fail-closed Ed25519 plugin manifest signing + strict discovery (`internal/plugin`)
- [x] SSRF protection for HTTP **and** gRPC upstreams (`internal/proxy/config`, `internal/authz/http.go`)
- [x] CRLF header-injection stripping on obligation headers (`internal/authz/engine.go`)
- [x] Policy fail-closed default (`policy_fallback_allow` = deny)
- [x] Signed cookies, `__Host-` prefix, `HttpOnly`/`Secure`/`SameSite` (`pkg/cookie`, `internal/auth`)
- [x] Secrets via env/files with placeholder rejection; Helm `secretKeyRef` (`internal/auth/config`, `deploy/helm`)
- [x] 32 MB request-body cap (`internal/authz/http.go`)
- [x] Private vulnerability disclosure process (`SECURITY.md`)

**Recommended before / at 1.0** — every item below is resolved (do-or-document):

- [x] **Documented.** Require `bundle_public_key_path` and `plugins_manifest_public_key_path` in production deployments — stated as required in the [Production profile](#5-production-profile-supported-10-stance) (§5) and reflected in `SECURITY.md`, README, and the Docker/Helm deploy assets.
- [x] **Done.** CodeQL is now blocking on `error`-level findings (`security.yml`; see §1). Warning-level stays informational.
- [x] **Documented (deferred).** Go public-API diff gate — explicitly out of scope for the 1.0 security-defaults wave and tracked as a follow-up alongside the existing proto/schema gates (§6).
- [x] **Documented.** Redis HA — managed-endpoint-only is formally the supported 1.0 topology ([Production profile](#5-production-profile-supported-10-stance) + [docs/REDIS-HA.md](REDIS-HA.md)); native Sentinel/Cluster support tracked as code follow-up **#107**.
- [x] **Documented.** `cookie_secure: true` is required in the [Production profile](#5-production-profile-supported-10-stance), with the explicit caveat that the `__Host-` prefix forces `Secure` only for prefixed cookie names — custom names must set it.
