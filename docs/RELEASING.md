# Releasing AccessGate

> How to cut a release of the AccessGate core repo (`github.com/accessgate/accessgate`).

This document is the source of truth for the release process. It describes the
flow that exists today: you push an annotated `v*` git tag, CI runs the test and
lint jobs, and [GoReleaser](https://goreleaser.com/) builds the
`accessgate-auth` and `accessgate-proxy` binaries, archives them, publishes them
to GitHub Releases, and builds and pushes multi-arch container images to the
GitHub Container Registry (GHCR).

On a `v*` tag it also produces **supply-chain artifacts**: an SBOM per archive,
a keyless [cosign](https://github.com/sigstore/cosign) signature of the checksums
file, keyless cosign signatures of the container images, and SLSA build
provenance attestations for the binaries and images (issue #45). See
[Supply-chain artifacts and verification](#supply-chain-artifacts-and-verification).

It documents only what the repository actually does. Anything not yet
implemented (changelog automation) lives under
[Future improvements](#future-improvements) and links to the
[roadmap](ROADMAP.md) rather than promising a date.

---

## Versioning policy

AccessGate follows [Semantic Versioning 2.0.0](https://semver.org/). Releases are
tagged `vMAJOR.MINOR.PATCH` (for example `v0.4.2`). The leading `v` is required —
the release CI job only runs for tags matching `v*`, and GoReleaser derives the
version from the tag.

Given a version `MAJOR.MINOR.PATCH`, bump the:

- **MAJOR** version for incompatible (breaking) changes to a public API: the Go
  packages importable under `github.com/accessgate/accessgate/...`, the
  command-line interfaces of `accessgate-auth` and `accessgate-proxy`, or the
  configuration schema (`schemas/auth.schema.json`, `schemas/proxy.schema.json`).
- **MINOR** version for backward-compatible new functionality (a new flag, a new
  config key with a safe default, a new exported function).
- **PATCH** version for backward-compatible bug fixes and internal changes that
  do not alter any public surface.

### Pre-1.0 caveat

AccessGate is pre-1.0. Per SemVer, anything in the `0.y.z` range is for initial
development and the public API should not be considered stable: APIs may evolve,
and breaking changes can land in **minor** (`0.y`) releases. Treat a `0.MINOR`
bump as the place breaking changes go while we are pre-1.0, and still call them
out explicitly in the release notes (see [the checklist](#pre-release-checklist)).
The "core runtime completeness" theme on the [roadmap](ROADMAP.md#themes) tracks
the subsystems that are still settling.

---

## Pre-release checklist

Run through this before you create the tag. The release CI job re-runs build and
tests as a safety net (see [What CI does](#what-ci-does)), but it does **not** run
`make go-check` or regenerate the config schemas, so verify those locally first.

- [ ] **`main` is green.** The commit you are about to tag is on `main` and its
      CI (`CI` and `Security` workflows) is passing.
- [ ] **Local checks pass.** Run `make go-check` (this runs `go fmt ./...`,
      `go vet ./...`, and `go test ./...`). Resolve anything it reports.
- [ ] **Config schemas are in sync.** Regenerate and confirm there is no drift:

      ```bash
      make schema
      git diff --exit-code schemas/
      ```

      `make schema` runs `go run ./cmd/schema`. If `git diff` shows changes, the
      committed schemas are stale — commit the regenerated `schemas/auth.schema.json`
      and `schemas/proxy.schema.json` before releasing.
- [ ] **Docs are updated.** Any new or changed flags, config keys, or behavior
      are reflected in the docs in the same release.
- [ ] **Breaking changes are noted.** Every backward-incompatible change is
      written down so it can go into the release notes (and, pre-1.0, so users of
      a `0.MINOR` bump know what to expect). There is no automated changelog yet
      (see [Future improvements](#future-improvements)). Breaking changes are
      mechanically surfaced by the contract gates that run on every PR — `buf
      breaking` for the protos, the `make schema` drift check for the config
      schemas, and the `apidiff` gate for the public Go API under `pkg/**` (see
      [`docs/COMPATIBILITY.md`](./COMPATIBILITY.md)) — so an intentional break
      should already have been flagged in review.
- [ ] **You picked the right version.** The bump matches the
      [versioning policy](#versioning-policy) above.

---

## Release steps

The release is driven entirely by pushing a tag. There is no manual upload step.

### 1. Create an annotated tag

From a clean checkout of the commit you want to release (on `main`, with the
[checklist](#pre-release-checklist) done):

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
```

Use an **annotated** tag (`-a`). The tag must start with `v` so the release job's
condition (`startsWith(github.ref, 'refs/tags/v')`) matches.

### 2. Push the tag

```bash
git push origin vX.Y.Z
```

Pushing the tag is what triggers the release. (Pushing the branch does not — the
release job only runs on a `v*` tag push.)

### 3. What CI does

The `CI` workflow (`.github/workflows/ci.yaml`) runs on the tag push. Its jobs:

1. **Test** and **Lint** run first (proto lint, generated-code and `go.mod`
   freshness checks, build, and `go test ./... -race -short`; plus
   `golangci-lint`).
2. **Release** runs only `if github.event_name == 'push'` and the ref starts with
   `refs/tags/v`, and only **after** Test and Lint succeed (`needs: [test, lint]`).
   It elevates `contents: write` **and `packages: write`** (the latter is required
   to push images to GHCR), checks out the tagged ref, sets up Go, regenerates
   protobuf code (`make proto-generate`), builds, and runs `go test ./... -short`.
   It then sets up **QEMU** and **Docker Buildx** (needed for cross-arch image
   builds) and logs in to **`ghcr.io`** with the workflow's `GITHUB_TOKEN`, before
   running GoReleaser:

   ```
   goreleaser release --clean
   ```

   GoReleaser authenticates to GitHub Releases with the same automatic
   `GITHUB_TOKEN` (no extra secret to configure), and uses the GHCR login above to
   push the container images and manifests.

   A separate **Docker build (PR validation)** job builds both images
   single-arch (`linux/amd64`) without pushing on every pull request, so the
   checked-in Dockerfiles are exercised before they reach a release.

If Test or Lint fails, the Release job does not run and nothing is published —
delete the tag, fix the problem, and re-tag.

### 4. Where artifacts land

GoReleaser creates a **GitHub Release** for the tag and uploads the built
archives and the checksums file as release assets. The release is created in the
repository's Releases page for that tag.

### 5. Add release notes

GoReleaser's config (`.goreleaser.yaml`) does not customize release-note
generation, so the release is created with default notes. Edit the GitHub Release
after it is published to add a human-readable summary:

- What changed (features, fixes), grouped for readability.
- **Breaking changes** and any migration steps, called out prominently — this is
  especially important pre-1.0, where breaking changes may appear in a `0.MINOR`
  bump.
- Links to relevant PRs/issues.

(Automating these notes is a [future improvement](#future-improvements).)

---

## Release artifacts

GoReleaser (`.goreleaser.yaml`) builds two binaries for three operating systems
and two architectures, then archives and checksums them.

**Binaries** (one `builds` entry each):

| Binary             | Source path              |
| ------------------ | ------------------------ |
| `accessgate-auth`  | `./cmd/accessgate-auth`  |
| `accessgate-proxy` | `./cmd/accessgate-proxy` |

**Platform matrix** (each binary, every combination):

| GOOS      | GOARCH          |
| --------- | --------------- |
| `linux`   | `amd64`, `arm64` |
| `darwin`  | `amd64`, `arm64` |
| `windows` | `amd64`, `arm64` |

**Archives:** one archive per binary per platform, named
`accessgate_{Version}_{Os}_{Arch}` (the `name_template` in `.goreleaser.yaml`).
The format is `.tar.gz`, overridden to `.zip` for Windows.

**Checksums:** a single `checksums.txt` covering all archives.

**SBOMs:** one [SPDX-JSON](https://spdx.dev/) SBOM per archive, named
`{archive}.sbom.json` (generated by [syft](https://github.com/anchore/syft) via
GoReleaser's `sboms:`).

**Signature + certificate:** `checksums.txt.sig` (detached cosign signature) and
`checksums.txt.pem` (the short-lived Sigstore signing certificate). Signing the
checksums file transitively covers every archive, since each archive's hash is
in `checksums.txt`.

All of the above are uploaded as assets on the GitHub Release for the tag. The
`snapshot` setting (`{{ incpatch .Version }}-next`) only affects local snapshot
builds (`goreleaser release --snapshot`); it is not used by the tag-driven
release.

---

## Container images

On a `v*` tag, the same GoReleaser run that builds the archives also builds and
pushes **multi-arch container images** to the GitHub Container Registry. This is
configured in `.goreleaser.yaml` (`dockers:` + `docker_manifests:`) and implemented
per [ADR-0005](adr/0005-container-image-tooling.md): images are built from the
checked-in multi-stage Dockerfiles in `build/docker/` (a `golang:1.26.x` builder
stage compiling a static binary onto `gcr.io/distroless/static:nonroot` — non-root,
no shell).

**Images** (one per binary):

| Image                                   | Built from                  |
| --------------------------------------- | --------------------------- |
| `ghcr.io/accessgate/accessgate-auth`    | `build/docker/Dockerfile.auth`  |
| `ghcr.io/accessgate/accessgate-proxy`   | `build/docker/Dockerfile.proxy` |

**Architectures:** `linux/amd64` and `linux/arm64`. Each arch is built as a
per-arch image (`:{Version}-amd64`, `:{Version}-arm64`) and the two are joined into
a single multi-arch manifest via `docker_manifests:`.

**Tags** published per release, for each image:

| Tag           | Example                                          | Notes                                  |
| ------------- | ------------------------------------------------ | -------------------------------------- |
| `{Version}`   | `ghcr.io/accessgate/accessgate-proxy:0.4.2`      | The release version (no leading `v`).  |
| `latest`      | `ghcr.io/accessgate/accessgate-proxy:latest`     | Moving tag, updated each release.       |

> The per-arch `:{Version}-amd64` / `:{Version}-arm64` tags are build
> intermediates that back the manifests; consume the version or `latest` tag.

Pull an image with:

```bash
docker pull ghcr.io/accessgate/accessgate-proxy:0.4.2
```

CI requirements for the image build live in the `release` job
(`.github/workflows/ci.yaml`): QEMU + Docker Buildx for cross-arch builds, a
`ghcr.io` login, and `packages: write` permission (see [What CI does](#what-ci-does)).

The images are **keyless-signed with cosign** and carry **SLSA build
provenance** — see [Supply-chain artifacts and
verification](#supply-chain-artifacts-and-verification) for how to verify them.

---

## Supply-chain artifacts and verification

On a `v*` tag the release job hardens the supply chain (issue #45). All signing
is **keyless** — cosign requests a short-lived certificate from the Sigstore
public-good CA (Fulcio) using the GitHub Actions OIDC identity and records the
signature in the Rekor transparency log. **There are no private keys to manage
or rotate.** This requires `id-token: write` (OIDC) and `attestations: write` on
the release job, plus the `sigstore/cosign-installer` and `syft` install steps.

What gets produced on each release:

| Artifact                       | What it is                                            | Where                    |
| ------------------------------ | ----------------------------------------------------- | ------------------------ |
| `{archive}.sbom.json`          | SPDX-JSON SBOM per archive (syft)                     | GitHub Release asset     |
| `checksums.txt.sig`            | Keyless cosign signature of `checksums.txt`           | GitHub Release asset     |
| `checksums.txt.pem`            | Sigstore signing certificate for the above            | GitHub Release asset     |
| Image signatures               | Keyless cosign signatures of the GHCR images (by digest) | OCI artifacts in GHCR |
| Build provenance attestations  | SLSA provenance for the binaries and the image digests | GitHub attestations / GHCR |

### Prerequisites

Install [cosign](https://github.com/sigstore/cosign) and the
[GitHub CLI](https://cli.github.com/) (`gh`, for provenance verification).

In the commands below, set the expected signer identity. The release is signed by
this repo's release job, so the certificate identity is the workflow ref and the
issuer is GitHub's OIDC provider:

```bash
IDENTITY='https://github.com/accessgate/accessgate/.github/workflows/ci.yaml@refs/tags/v0.4.2'
ISSUER='https://token.actions.githubusercontent.com'
```

(You can match a family of tags with a regexp instead of an exact identity — see
`--certificate-identity-regexp` below.)

### Verify the checksums signature (and thus the archives)

Download `checksums.txt`, `checksums.txt.sig`, and `checksums.txt.pem` from the
release, then:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  checksums.txt
```

A successful `Verified OK` means `checksums.txt` is authentic. Then verify an
archive against it the usual way (its hash must appear in the verified file):

```bash
sha256sum --check --ignore-missing checksums.txt
```

### Verify a container image

cosign resolves the signature stored alongside the image in GHCR. Use an
identity **regexp** so any `v*` tag of this repo matches:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/accessgate/accessgate/\.github/workflows/ci\.yaml@refs/tags/v.*$' \
  --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/accessgate/accessgate-proxy:0.4.2
```

Repeat for `accessgate-auth`. Pin by digest (`...@sha256:...`) for the strongest
guarantee.

### Verify build provenance

SLSA build provenance is attached as a GitHub attestation (binaries) and pushed
to GHCR (images). Verify with `gh`:

```bash
# A released binary archive:
gh attestation verify accessgate_0.4.2_linux_amd64.tar.gz \
  --repo accessgate/accessgate

# A container image (reads the attestation from the registry):
gh attestation verify oci://ghcr.io/accessgate/accessgate-proxy:0.4.2 \
  --repo accessgate/accessgate
```

`gh attestation verify` confirms the artifact was built by this repo's CI and
reports the source commit and workflow.

---

## Future improvements

These are planned but **not implemented**. They are tracked on the
[roadmap](ROADMAP.md) — this section links to those items rather than committing
to scope or dates here.

- **Changelog / release-note automation.** Today release notes are written by
  hand on the GitHub Release. Conventions for, and automation of, release notes
  are part of the "Release process" item under
  [Next on the roadmap](ROADMAP.md#next) (`area/packaging`).

> **Implemented (issue #45):** Artifact and image **signing, SBOMs, and SLSA
> provenance** now ship on every `v*` release — see [Supply-chain artifacts and
> verification](#supply-chain-artifacts-and-verification). Signing is keyless
> (Sigstore/cosign via GitHub OIDC), so there are no keys to manage.

When any of these land, update this document so it continues to describe only
what the repository actually does.
