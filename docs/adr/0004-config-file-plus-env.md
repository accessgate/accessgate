# ADR-0004: Configuration via file plus environment (env overrides file)

- **Status**: Accepted
- **Date**: 2026-06-05

## Context

AccessGate runs in containers and in local development. Operators want a readable base
configuration file (checked into deployment repos or mounted as a config map) while still
being able to override individual values per environment — typically with environment
variables and secrets injected by the orchestrator. We also want the two binaries to load
config the same way and to expose a machine-readable schema for validation and tooling.

## Decision

Both binaries load configuration through a single pipeline, `configload.LoadInto`
(`internal/configload/load.go`), built on `go-config`:

1. If a config path is provided, an optional file source is added — JSON or YAML, selected by
   file extension.
2. An environment source is always added.
3. Sources are merged with **later sources winning, so environment variables override file
   values**. The result is decoded into the binary's config struct, after which
   `ApplyDefaults` and `Validate` run.

**Config-path resolution** is per binary:

- `accessgate-auth` (`loadConfig` in `cmd/accessgate-auth/main.go`): `CONFIG_PATH` →
  `AUTH_CONFIG` → `AGENT_CONFIG`. The `AGENT_CONFIG` name is a **deprecated alias** retained
  for backward compatibility (the Makefile likewise accepts `BINARY=agent` as an alias for
  `auth`).
- `accessgate-proxy` (`loadConfig` in `cmd/accessgate-proxy/main.go`): `CONFIG_PATH` →
  `PROXY_CONFIG`.

If no path is set, the binary runs from environment variables only. Config booleans accept
both real booleans and string forms (`"true"`, `"1"`, `"yes"`) via `FlexibleBool`, easing
env-based overrides.

**Schema generation**: `make schema` runs `cmd/schema/main.go`, which uses the go-config
schema extension to emit `schemas/auth.schema.json` and `schemas/proxy.schema.json` directly
from the Go config structs. Companion targets `validate-config`, `print-schema`, and
`render-config-example` build on the same structs.

## Consequences

- One predictable layering model ("env overrides file") works for both committed base files
  and per-environment overrides, including secrets injected as env vars.
- Both binaries share the loader, so config behavior is consistent and tested in one place.
- Generated JSON Schemas keep documentation and validation in lockstep with the code, since
  they are derived from the actual config structs rather than maintained by hand.
- Cost: the `AGENT_CONFIG`/`agent` aliases carry historical naming that must be kept working
  (or removed deliberately with a deprecation window); supporting both JSON and YAML plus
  flexible scalar parsing adds surface area to the loader.
