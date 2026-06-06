package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// benchRegoSrc is a tiny deterministic policy: allow /public, deny everything
// else. It mirrors the fixture used in rego_test.go so the benchmark exercises
// both decision branches of a compiled Rego module.
const benchRegoSrc = `
package accessgate

decision := {"allow": true, "status_code": 200, "reason": "", "headers": {}, "obligations": {}} if {
  input.Path == "/public"
} else := {"allow": false, "status_code": 403, "reason": "denied by policy", "headers": {}, "obligations": {}} if {
  true
}
`

// loadBenchRego compiles the fixture policy into a RegoEngine. Compilation
// happens once, outside the timed loop, so the benchmark measures evaluation.
func loadBenchRego(b *testing.B) *RegoEngine {
	b.Helper()
	dir := b.TempDir()
	p := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(p, []byte(benchRegoSrc), 0o600); err != nil {
		b.Fatalf("write rego: %v", err)
	}
	eng := NewRegoEngine(DefaultFallbackDeny)
	if err := eng.Load(p); err != nil {
		b.Fatalf("Load: %v", err)
	}
	return eng
}

// BenchmarkPolicyEvaluate_Rego measures a single Evaluate against a compiled
// Rego module on both the allow (/public) and deny (/admin) branches.
func BenchmarkPolicyEvaluate_Rego(b *testing.B) {
	eng := loadBenchRego(b)
	ctx := context.Background()

	b.Run("Allow", func(b *testing.B) {
		in := Input{Protocol: "http", Method: "GET", Path: "/public"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dec, err := eng.Evaluate(ctx, in)
			if err != nil || !dec.Allow {
				b.Fatalf("unexpected: dec=%#v err=%v", dec, err)
			}
		}
	})

	b.Run("Deny", func(b *testing.B) {
		in := Input{Protocol: "http", Method: "GET", Path: "/admin"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dec, err := eng.Evaluate(ctx, in)
			if err != nil || dec.Allow {
				b.Fatalf("unexpected: dec=%#v err=%v", dec, err)
			}
		}
	})
}

// BenchmarkPolicyEvaluate_WASM measures the WASM runtime's evaluate path.
//
// No checked-in WASM policy bundle fixture exists yet, so this benchmark
// exercises the no-module fallback path (input marshal guard -> fallback
// decision), which is deterministic and hermetic. Benchmarking a real compiled
// bundle end-to-end (host call + JSON round-trip across linear memory) is a
// follow-up once a small fixture bundle is committed; see docs/BENCHMARKING.md.
func BenchmarkPolicyEvaluate_WASM(b *testing.B) {
	w := NewWASMRuntime(DefaultFallbackDeny)
	ctx := context.Background()
	in := Input{Protocol: "http", Method: "GET", Path: "/api/v1/resource"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec, err := w.Evaluate(ctx, in)
		if err != nil || dec.Allow {
			b.Fatalf("unexpected: dec=%#v err=%v", dec, err)
		}
	}
}
