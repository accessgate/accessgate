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
| `BenchmarkPolicyEvaluate_WASM` | `internal/policy` | A single `WASMRuntime.Evaluate` against the committed WASM bundle fixture (`internal/policy/testdata/bench_policy.wasm`), on both allow and deny branches. Exercises the real end-to-end path: input marshal → write into linear memory → exported `evaluate` host call → read + unmarshal decision JSON. Instantiation happens once outside the timed loop. |
| `BenchmarkPolicyEvaluate_WASMFallback` | `internal/policy` | The `WASMRuntime.Evaluate` no-module fallback path (no bundle loaded, no host call) — the cheap floor for comparison. |

The engine benchmarks use a stub `PrincipalResolver` and an in-memory
`policy.Engine` so they isolate the engine's own decision/header work from
policy-evaluation cost. The `BenchmarkPolicyEvaluate_*` benchmarks measure
policy evaluation in isolation.

## WASM bundle fixture

`BenchmarkPolicyEvaluate_WASM` now runs against a committed WASM policy bundle
fixture, `internal/policy/testdata/bench_policy.wasm` (~264 bytes). It is a
purpose-built module implementing the runtime's custom ABI (`memory` +
`evaluate(input_ptr,input_len)->(out_ptr,out_len)`), **not** an OPA-compiled
bundle — OPA's WASM ABI is incompatible with this loader. It branches on the
request Path (`/public` → allow 200, else deny 403) and is loaded unsigned (no
test keypair or signature is committed).

Regenerate the fixture (deterministic, no external toolchain) with:

```sh
go run ./internal/policy/testdata/gen
```

See `internal/policy/testdata/README.md` for the full ABI / layout notes.

## v1.0 local baseline

Captured with `go test -run '^$' -bench=BenchmarkPolicyEvaluate -benchmem
-count=3 ./internal/policy/...`. **Local baseline only** — these are
single-machine reference numbers, not a CI gate or release SLO. Machine: AMD
Ryzen 5 3600 (6-core / 12-thread), Windows, Go 1.26, `GOMAXPROCS=12`. Figures
below are representative of the 3-run sample.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `PolicyEvaluate_Rego/Allow` | ~16,400 | 7,786 | 135 |
| `PolicyEvaluate_Rego/Deny` | ~17,600 | 7,860 | 138 |
| `PolicyEvaluate_WASM/Allow` | ~11,900 | 12,503 | 15 |
| `PolicyEvaluate_WASM/Deny` | ~12,400 | 12,519 | 16 |
| `PolicyEvaluate_WASMFallback` | ~53 | 48 | 1 |

Notes:

- The WASM real-bundle path is ~225x the cost of the no-module fallback (~53
  ns), confirming the benchmark now measures genuine evaluation (host call +
  JSON round-trip across linear memory) rather than the fallback shortcut.
- WASM evaluation is somewhat faster per op than Rego here but allocates more
  bytes (the wazero memory read/instantiation buffers) at far fewer
  allocations. Treat cross-engine comparisons as indicative only — the fixtures
  encode different policies.
- Re-run on your own hardware before quoting numbers; absolute values vary with
  CPU, OS, and Go version.
