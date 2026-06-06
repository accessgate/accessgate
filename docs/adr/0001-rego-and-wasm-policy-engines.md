# ADR-0001: Support both Rego and WASM policy engines

- **Status**: Accepted
- **Date**: 2026-06-05

## Context

The proxy must make an allow/deny decision for every request, and policy authors have
different needs. Some teams already write OPA/Rego and want to reuse it; others want to ship
compiled, language-agnostic policy artifacts that can be signed and distributed without
exposing source. Forcing one model would alienate one of these audiences.

We also need a hard safety guarantee: if a policy is missing, malformed, or errors at
evaluation time, the system must not "fail open."

## Decision

We support two interchangeable policy backends behind a single `policy.Engine` interface
(`internal/policy/engine.go`), selected at proxy startup by the `policy_engine` config value
(`buildPolicyEngine` in `cmd/accessgate-proxy/main.go`):

- **Rego** (`internal/policy/rego.go`) — OPA embedded via `open-policy-agent/opa/v1`. The
  policy must declare `package accessgate`; the engine evaluates the query
  `data.accessgate.decision`.
- **WASM** (`internal/policy/wasm.go`, `internal/policy/bundle.go`) — bundles compiled to
  WebAssembly and executed on `wazero`. A module must export linear `memory` and
  `evaluate(input_ptr, input_len) -> (output_ptr, output_len)`. `BundleLoader` compiles and
  caches by path + mtime and accepts a PEM public key (`bundle_public_key_path`). When a
  key is configured it verifies the bundle's detached Ed25519 signature (`<bundle>.sig`)
  before compiling/instantiating, failing closed on any verification failure; when no key
  is configured it logs a warning and loads unsigned.

Both engines share one contract: they consume the same `policy.Input` and return the same
`policy.Decision` `{ allow, status_code, reason, headers, obligations }`. This lets the rest
of the proxy (`DefaultEngine.Handle`) stay engine-agnostic.

The default engine is `wasm`, and every engine **fails closed**: when no policy is loaded or
evaluation fails, it returns the configured `FallbackConfig`, which defaults to **deny with
503**. Allowing unevaluated requests requires an explicit `policy_fallback_allow: true`.

## Consequences

- Teams can adopt AccessGate with their existing Rego, or ship signed, opaque WASM bundles.
- A stable, documented decision contract decouples policy authoring from the runtime and
  keeps both engines drop-in compatible.
- Fail-closed-by-default means a broken or missing policy blocks traffic rather than leaking
  it — the safer failure mode for an authz gate.
- Cost: two engine integrations to maintain, two sets of authoring docs/tests, and the
  shared `Decision` shape becomes a compatibility surface that must evolve carefully.
- WASM signature verification is enforced when `bundle_public_key_path` is set: bundles
  with a missing, malformed, or invalid signature are rejected (fail-closed, no fallback to
  loading unverified). Operators who leave the key unset accept unsigned loading and the
  logged warning. See `docs/GUIDE-POLICY-SIGNING.md`.
