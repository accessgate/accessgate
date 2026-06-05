# Contributing to AccessGate

Thanks for your interest in AccessGate — a policy-driven authentication and
authorization runtime (the `accessgate-auth` and `accessgate-proxy` binaries).
This guide covers how to set up, make a change, and get it reviewed.

## Prerequisites

- **Go** (see the version in [`go.mod`](go.mod); currently the 1.25+ toolchain)
- **Make**
- **buf** (optional — the `Makefile` falls back to `go run` if it is not on `PATH`)
- **Docker** + **docker-compose** (optional, for `make e2e-docker`)

## Getting started

```bash
git clone https://github.com/accessgate/accessgate.git
cd accessgate
go build ./cmd/accessgate-auth ./cmd/accessgate-proxy
go test ./...
```

Run a binary with config from a file and/or environment variables:

```bash
CONFIG_PATH=configs/auth.example.yaml  ./accessgate-auth
CONFIG_PATH=configs/proxy.example.yaml ./accessgate-proxy
```

## Common tasks

The `Makefile` is the source of truth. Frequently used targets:

| Command | Purpose |
|---------|---------|
| `make test` / `go test ./...` | Run the test suite |
| `go test -run TestName ./internal/authz` | Run a single test |
| `make go-check` | `go fmt` + `go vet` + `go test` — run before committing |
| `make schema` | Regenerate `schemas/{auth,proxy}.schema.json` from the config structs |
| `make validate-config CONFIG_PATH=… BINARY=auth\|proxy` | Validate a config file |
| `make proto-lint` / `make proto-generate` | Lint / regenerate protobuf bindings |
| `make proto-breaking` | Check for breaking proto changes vs `main` |
| `make e2e-docker` | Bring up compose, run the E2E playbook, tear down |

If you change a **config struct**, run `make schema` and commit the regenerated
schema. If you change a **`.proto`** file, run `make proto-generate` and commit
the regenerated `proto/gen/**` (never hand-edit generated code).

## Branch & change discipline

This project follows the operating model in [`AGENTS.md`](AGENTS.md) and `agents/`:

- **Never commit directly to `main`.** Branch per change.
- Keep one issue-sized slice per branch. Don't mix unrelated refactors with bug fixes.
- Don't bundle unrelated repositories in one branch.
- Don't overwrite unrelated dirty work or revert changes you didn't make.

### Branch naming

`feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`, `test/<slug>`,
`refactor/<slug>`.

### Commits

Use clear, conventional-style messages (`feat(proxy): …`, `fix(auth): …`,
`docs: …`, `chore: …`). Keep generated-code regeneration in its own commit.

## Pull requests

Open PRs against `main`. The PR template asks for: summary, scope, testing /
verification evidence, migration impact, and docs impact. Before requesting review:

1. `make go-check` passes.
2. `make proto-lint` passes (and generated code is up to date if protos changed).
3. New behavior has tests; backend/API changes include request/response or test evidence.
4. Docs updated where behavior or config changed.

CI (`.github/workflows/ci.yaml`) runs tests + lint + proto checks; the security
workflow runs `govulncheck` and CodeQL. All checks must be green before merge.

## Naming & lineage

AccessGate is the canonical product identity. Use **AccessGate** in current-state
docs and code. The names **AuthSentinel** (legacy monorepo ancestor) and
**PolicyFront** (earlier ecosystem split) appear only as historical/migration
provenance — see [`docs/LINEAGE.md`](docs/LINEAGE.md) and
[`docs/MIGRATION.md`](docs/MIGRATION.md).

## Reporting bugs & security issues

- **Bugs / features**: open a GitHub issue using the templates in `.github/ISSUE_TEMPLATE/`.
- **Security vulnerabilities**: do **not** open a public issue — follow [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree your contributions are licensed under the repository's
license (Apache-2.0; see `LICENSE`).
