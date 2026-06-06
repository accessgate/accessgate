# Benchmarking

AccessGate ships Go benchmarks (`go test -bench`) covering the proxy request
hot path so release notes can cite concrete numbers. The harness is a spike
(roadmap #82): it produces numbers on demand and is **not** a CI gate. Wiring
performance budgets / regression checks into CI is tracked separately (#50).

All benchmarks are hermetic — no network, Redis, or external processes. They use
the same in-memory fakes and fixtures as the unit tests, so they are
deterministic and safe to run anywhere.

## How to run

```sh
go test -bench=. -benchmem ./internal/authz/... ./internal/policy/...
```

Useful variations:

```sh
# Stabilize results with a fixed run count / time.
go test -run '^$' -bench=. -benchmem -count=3 ./internal/authz/... ./internal/policy/...

# Run a single benchmark.
go test -run '^$' -bench=BenchmarkEngineHandle_Allow -benchmem ./internal/authz/...
```

`-run '^$'` disables unit tests so only benchmarks run; `-benchmem` reports
`B/op` and `allocs/op` alongside `ns/op` (every benchmark also calls
`b.ReportAllocs()`).

## What each benchmark covers

| Benchmark | Package | Covers |
|---|---|---|
| `BenchmarkEngineHandle_Allow` | `internal/authz` | Full `DefaultEngine.Handle` on the allow path: stub principal resolve → policy eval (in-memory) → response + upstream header build. |
| `BenchmarkEngineHandle_Deny` | `internal/authz` | Full `DefaultEngine.Handle` on the deny path, including reason-bearing JSON error body construction. |
| `BenchmarkNormalizeRequest` | `internal/authz` | `NormalizeRequest` parsing across three shapes: GraphQL JSON body, raw GraphQL document, and gRPC `:path` pseudo-header. |
| `BenchmarkPolicyEvaluate_Rego` | `internal/policy` | A single `RegoEngine.Evaluate` against a compiled tiny fixture policy, on both allow and deny branches. Compilation happens once outside the timed loop. |
| `BenchmarkPolicyEvaluate_WASM` | `internal/policy` | The `WASMRuntime.Evaluate` no-module fallback path (see note below). |

The engine benchmarks use a stub `PrincipalResolver` and an in-memory
`policy.Engine` so they isolate the engine's own decision/header work from
policy-evaluation cost. The `BenchmarkPolicyEvaluate_*` benchmarks measure
policy evaluation in isolation.

## Known follow-up: real WASM bundle

There is no checked-in WASM policy bundle fixture, so
`BenchmarkPolicyEvaluate_WASM` currently exercises only the deterministic
no-module fallback path. Benchmarking a real compiled bundle end-to-end (host
function call plus the JSON round-trip across the module's linear memory)
requires committing a small fixture bundle and is left as a follow-up.
