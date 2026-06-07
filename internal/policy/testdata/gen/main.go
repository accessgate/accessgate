// Command gen produces bench_policy.wasm: a tiny, hand-assembled WebAssembly
// module that implements the policy runtime's custom ABI so that
// BenchmarkPolicyEvaluate_WASM can measure a *real* evaluation (host call plus
// the JSON round-trip across the module's linear memory) instead of the
// no-module fallback path.
//
// This is deliberately NOT an OPA-compiled bundle. The AccessGate WASM runtime
// (internal/policy/wasm.go) defines its own minimal ABI:
//
//	exports: "memory" and "evaluate(input_ptr i32, input_len i32) -> (out_ptr i32, out_len i32)"
//
// which is incompatible with OPA's WASM ABI (opa_eval/opa_malloc/...). The
// smallest fixture that exercises the real path is therefore a purpose-built
// module, assembled here from raw bytes so it has zero toolchain dependencies
// (no wat2wasm / wabt / OPA needed to regenerate).
//
// Behavior: the runtime writes the marshaled Input JSON at memory offset 0. For
// the benchmark inputs (Protocol "http", Method "GET") the JSON is
//
//	{"Protocol":"http","Method":"GET","Path":"/<...>",...}
//
// so the leading '/' of the Path value is always at byte offset 42 and the
// character after it at offset 43. The module branches on byte 43: 'p' (from
// "/public") -> allow 200, anything else -> deny 403. Each branch returns a
// pointer/length into a data segment
// holding the corresponding decision JSON, which the runtime then reads back and
// unmarshals — exercising input read, branch, and output read across linear
// memory.
//
// Regenerate with:
//
//	go run ./internal/policy/testdata/gen
//
// from the repo root (writes internal/policy/testdata/bench_policy.wasm).
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Decision JSON written back to the runtime. Field set matches the struct the
// runtime unmarshals in wasm.go (allow/status_code/reason/obligations/headers).
const (
	allowJSON = `{"allow":true,"status_code":200,"reason":"","obligations":{},"headers":{}}`
	denyJSON  = `{"allow":false,"status_code":403,"reason":"denied by policy","obligations":{},"headers":{}}`
)

// dataOffset is where the decision-JSON data segment is placed in linear memory.
// It must sit above the region the runtime uses for the input (it writes the
// input JSON at offset 0; benchmark inputs are ~140 bytes), so 2048 is safe.
const dataOffset = 2048

// pathByteOffset is the offset of the Path value's leading '/' in the marshaled
// benchmark Input JSON (see package doc). The module branches on the byte
// immediately after it (pathByteOffset+1): 'p' for "/public", else deny.
const pathByteOffset = 42

func uleb(n uint32) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func sleb(n int32) []byte {
	var out []byte
	more := true
	for more {
		b := byte(n & 0x7f)
		n >>= 7
		if (n == 0 && b&0x40 == 0) || (n == -1 && b&0x40 != 0) {
			more = false
		} else {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

func section(id byte, body []byte) []byte {
	out := []byte{id}
	out = append(out, uleb(uint32(len(body)))...)
	return append(out, body...)
}

func vec(items [][]byte) []byte {
	out := uleb(uint32(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func main() {
	const (
		i32        = 0x7f
		funcType   = 0x60
		opLocGet   = 0x20
		opI32Eq    = 0x46
		opI32Const = 0x41
		opLoad8U   = 0x2d
		opSelect   = 0x1b
		opEnd      = 0x0b
	)

	allowPtr := uint32(dataOffset)
	denyPtr := uint32(dataOffset + len(allowJSON))
	dataBytes := append([]byte(allowJSON), []byte(denyJSON)...)

	// --- Type section: one type (i32,i32)->(i32,i32) ---
	ft := []byte{funcType}
	ft = append(ft, uleb(2)...) // params
	ft = append(ft, i32, i32)
	ft = append(ft, uleb(2)...) // results
	ft = append(ft, i32, i32)
	typeSec := section(0x01, vec([][]byte{ft}))

	// --- Function section: one function, type 0 ---
	funcSec := section(0x03, vec([][]byte{uleb(0)}))

	// --- Memory section: one memory, min 1 page ---
	memEntry := append([]byte{0x00}, uleb(1)...) // flags=0 (min only), min=1
	memSec := section(0x05, vec([][]byte{memEntry}))

	// --- Export section: "memory" (mem 0) and "evaluate" (func 0) ---
	expMem := append(append([]byte{}, uleb(uint32(len("memory")))...), []byte("memory")...)
	expMem = append(expMem, 0x02, 0x00) // kind=mem, index 0
	expFn := append(append([]byte{}, uleb(uint32(len("evaluate")))...), []byte("evaluate")...)
	expFn = append(expFn, 0x00, 0x00) // kind=func, index 0
	exportSec := section(0x07, vec([][]byte{expMem, expFn}))

	// --- Code section ---
	// Body uses `select` (avoids needing a multi-value block type):
	//   cond    = (mem[input_ptr + pathByteOffset+1] == 'p')   // 'p' from "/public"
	//   out_ptr = select(allowPtr, denyPtr, cond)
	//   out_len = select(allowLen, denyLen, cond)
	// `select` pops a, b, cond and pushes (cond ? a : b). The two results are
	// left on the stack in order (out_ptr, out_len) for the (i32,i32) return.
	// Since the runtime writes the input JSON at memory offset 0, input_ptr is 0
	// and the effective load address is pathByteOffset+1.
	body := []byte{}
	body = append(body, uleb(0)...) // no locals
	// out_ptr
	body = append(body, opI32Const)
	body = append(body, sleb(int32(allowPtr))...)
	body = append(body, opI32Const)
	body = append(body, sleb(int32(denyPtr))...)
	body = append(body, opLocGet, 0x00) // input_ptr
	body = append(body, opLoad8U, 0x00)
	body = append(body, uleb(pathByteOffset+1)...)
	body = append(body, opI32Const)
	body = append(body, sleb('p')...) // 'p' = 0x70 (needs 2-byte SLEB)
	body = append(body, opI32Eq)
	body = append(body, opSelect)
	// out_len
	body = append(body, opI32Const)
	body = append(body, sleb(int32(len(allowJSON)))...)
	body = append(body, opI32Const)
	body = append(body, sleb(int32(len(denyJSON)))...)
	body = append(body, opLocGet, 0x00)
	body = append(body, opLoad8U, 0x00)
	body = append(body, uleb(pathByteOffset+1)...)
	body = append(body, opI32Const)
	body = append(body, sleb('p')...)
	body = append(body, opI32Eq)
	body = append(body, opSelect)
	body = append(body, opEnd)

	funcBody := append(uleb(uint32(len(body))), body...)
	codeSec := section(0x0a, vec([][]byte{funcBody}))

	// --- Data section: active segment at dataOffset ---
	seg := []byte{0x00} // memory index 0, active
	seg = append(seg, opI32Const)
	seg = append(seg, sleb(int32(dataOffset))...)
	seg = append(seg, opEnd)
	seg = append(seg, uleb(uint32(len(dataBytes)))...)
	seg = append(seg, dataBytes...)
	dataSec := section(0x0b, vec([][]byte{seg}))

	// --- Assemble module ---
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00} // magic + version
	out = append(out, typeSec...)
	out = append(out, funcSec...)
	out = append(out, memSec...)
	out = append(out, exportSec...)
	out = append(out, codeSec...)
	out = append(out, dataSec...)

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	// Resolve output path relative to repo root regardless of cwd.
	outPath := filepath.Join(dir, "internal", "policy", "testdata", "bench_policy.wasm")
	if _, statErr := os.Stat(filepath.Join(dir, "internal", "policy", "testdata")); statErr != nil {
		// running from within testdata/gen
		outPath = filepath.Join(dir, "..", "bench_policy.wasm")
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s (%d bytes); allowPtr=%d denyPtr=%d allowLen=%d denyLen=%d\n",
		outPath, len(out), allowPtr, denyPtr, len(allowJSON), len(denyJSON))
}
