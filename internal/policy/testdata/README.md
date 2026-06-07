# internal/policy testdata

## `bench_policy.wasm`

A tiny (~264 byte) WebAssembly policy bundle fixture used by
`BenchmarkPolicyEvaluate_WASM` so the benchmark measures a **real** evaluation
(host function call plus the input/output JSON round-trip across the module's
linear memory) instead of only the no-module fallback path.

### Why it is hand-assembled, not OPA-compiled

The AccessGate WASM runtime (`internal/policy/wasm.go`) defines its **own
minimal ABI**, not OPA's. A loaded module must export:

- `memory`
- `evaluate(input_ptr i32, input_len i32) -> (out_ptr i32, out_len i32)`

The runtime writes the marshaled `policy.Input` JSON at memory offset 0, calls
`evaluate`, then reads `out_len` bytes of decision JSON starting at `out_ptr`.
An OPA `opa build -t wasm` bundle exports the OPA ABI (`opa_eval`, `opa_malloc`,
…) and would be rejected by this loader (`module must export "evaluate"`).

The fixture is therefore a purpose-built module assembled from raw bytes by a
small Go generator, which keeps it tiny and dependency-free (no `wat2wasm` /
`wabt` / OPA needed to regenerate).

### Behavior

The benchmark inputs all use `Protocol:"http"`, `Method:"GET"`, so the marshaled
JSON is `{"Protocol":"http","Method":"GET","Path":"/<...>",...}` and the leading
`/` of the Path value is always at byte offset 42. The module branches on the
byte at offset 43 (the character after the slash):

- `'p'` (from `"/public"`) -> allow, `{"allow":true,"status_code":200,...}`
- anything else (e.g. `"/admin"`) -> deny, `{"allow":false,"status_code":403,"reason":"denied by policy",...}`

It is loaded **unsigned**: the runtime's `Load(path)` / a `BundleLoader` with no
configured public key both load unsigned bundles, so no test keypair or
signature file is committed.

### Regenerate

From the repo root:

```sh
go run ./internal/policy/testdata/gen
```

This rewrites `internal/policy/testdata/bench_policy.wasm`. The output is
deterministic. See `gen/main.go` for the full module layout and ABI notes.
