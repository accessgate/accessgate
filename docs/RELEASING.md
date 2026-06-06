# Releasing AccessGate

> How to cut a release of the AccessGate core repo (`github.com/accessgate/accessgate`).

This document is the source of truth for the release process. It describes the
flow that exists today: you push an annotated `v*` git tag, CI runs the test and
lint jobs, and [GoReleaser](https://goreleaser.com/) builds the
`accessgate-auth` and `accessgate-proxy` binaries, archives them, and publishes
them to GitHub Releases.

It documents only what the repository actually does. Anything not yet
implemented (changelog automation, signing, container images) lives under
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
      (see [Future improvements](#future-improvements)).
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
   It elevates `contents: write`, checks out the tagged ref, sets up Go,
   regenerates protobuf code (`make proto-generate`), builds, runs
   `go test ./... -short`, and then runs GoReleaser:

   ```
   goreleaser release --clean
   ```

   GoReleaser authenticates to GitHub with the workflow's automatic
   `GITHUB_TOKEN` (no extra secret to configure).

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

All of the above are uploaded as assets on the GitHub Release for the tag. The
`snapshot` setting (`{{ incpatch .Version }}-next`) only affects local snapshot
builds (`goreleaser release --snapshot`); it is not used by the tag-driven
release.

> **Not produced today:** container images. The comment in `.goreleaser.yaml`
> ("Docker images via separate workflow") is aspirational — no such workflow
> exists in this repo yet. See [Future improvements](#future-improvements).

---

## Future improvements

These are planned but **not implemented**. They are tracked on the
[roadmap](ROADMAP.md) — this section links to those items rather than committing
to scope or dates here.

- **Changelog / release-note automation.** Today release notes are written by
  hand on the GitHub Release. Conventions for, and automation of, release notes
  are part of the "Release process" item under
  [Next on the roadmap](ROADMAP.md#next) (`area/packaging`).
- **Artifact signing and SLSA provenance.** Releases are not signed and do not
  carry build provenance today. SBOM generation and build provenance (e.g. SLSA)
  in the release workflow are tracked under
  [Later on the roadmap](ROADMAP.md#later) (supply-chain provenance,
  `area/packaging`), and align with the "Security & supply chain" theme.
- **Container images.** No image build/publish workflow exists yet. Packaging
  work, including consolidating how the project is built and distributed, sits
  within the "Ecosystem & consolidation" theme on the [roadmap](ROADMAP.md#themes).

When any of these land, update this document so it continues to describe only
what the repository actually does.
