package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// FallbackConfig configures behavior when no policy is loaded or evaluation fails.
type FallbackConfig struct {
	// Allow when true means fallback is allow; when false fallback is deny with 503.
	Allow bool
}

// DefaultFallbackDeny is a fallback that denies with 503.
var DefaultFallbackDeny = FallbackConfig{Allow: false}

// DefaultFallbackAllow is a fallback that allows with 200.
var DefaultFallbackAllow = FallbackConfig{Allow: true}

// WASMRuntime runs policy bundles compiled to WASM.
// ABI: module exports "memory" and "evaluate(input_ptr i32, input_len i32) -> (output_ptr i32, output_len i32)".
// Input and output are JSON; output shape: {"allow": bool, "status_code": int, "reason": string, "obligations": {...}}
type WASMRuntime struct {
	mu         sync.RWMutex
	runtime    wazero.Runtime
	compiled   wazero.CompiledModule
	module     api.Module
	fallback   FallbackConfig
	bundlePath string // set when Load(path) is used
}

// NewWASMRuntime creates a WASM runtime with the given fallback behavior.
func NewWASMRuntime(fallback FallbackConfig) *WASMRuntime {
	return &WASMRuntime{
		runtime:  wazero.NewRuntime(context.Background()),
		fallback: fallback,
	}
}

// NewWASMRuntimeWithRuntime creates a WASM runtime using an existing wazero.Runtime (e.g. from BundleLoader).
func NewWASMRuntimeWithRuntime(rt wazero.Runtime, fallback FallbackConfig) *WASMRuntime {
	return &WASMRuntime{runtime: rt, fallback: fallback}
}

// Load loads a policy bundle (WASM binary) from path. Replaces any previously loaded module.
func (w *WASMRuntime) Load(path string) error {
	wasm, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy: read wasm: %w", err)
	}
	ctx := context.Background()
	compiled, err := w.runtime.CompileModule(ctx, wasm)
	if err != nil {
		return fmt.Errorf("policy: compile wasm: %w", err)
	}
	w.mu.Lock()
	w.bundlePath = path
	w.mu.Unlock()
	return w.loadCompiled(compiled)
}

// loadCompiled instantiates a pre-compiled module. Used by BundleLoader.
func (w *WASMRuntime) loadCompiled(compiled wazero.CompiledModule) error {
	ctx := context.Background()
	module, err := w.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return fmt.Errorf("policy: instantiate wasm: %w", err)
	}
	if module.ExportedFunction("evaluate") == nil {
		_ = module.Close(ctx)
		return fmt.Errorf("policy: wasm module must export \"evaluate\"")
	}
	if module.ExportedMemory("memory") == nil {
		_ = module.Close(ctx)
		return fmt.Errorf("policy: wasm module must export \"memory\"")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.module != nil {
		_ = w.module.Close(ctx)
	}
	w.compiled = compiled
	w.module = module
	return nil
}

// Evaluate runs the loaded WASM policy with the given input. If no module is loaded or evaluation fails, returns fallback decision.
func (w *WASMRuntime) Evaluate(ctx context.Context, input Input) (*Decision, error) {
	w.mu.RLock()
	module := w.module
	w.mu.RUnlock()

	if module == nil {
		return w.fallbackDecision(), nil
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return w.fallbackDecision(), nil
	}

	mem := module.ExportedMemory("memory")
	if mem == nil {
		return w.fallbackDecision(), nil
	}
	if !mem.Write(0, inputJSON) {
		return w.fallbackDecision(), nil
	}

	eval := module.ExportedFunction("evaluate")
	if eval == nil {
		return w.fallbackDecision(), nil
	}
	results, err := eval.Call(ctx, 0, uint64(len(inputJSON)))
	if err != nil || len(results) != 2 {
		return w.fallbackDecision(), nil
	}
	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	if outLen == 0 {
		return w.fallbackDecision(), nil
	}
	outBuf, ok := mem.Read(outPtr, outLen)
	if !ok {
		return w.fallbackDecision(), nil
	}
	var out struct {
		Allow       bool              `json:"allow"`
		StatusCode  int               `json:"status_code"`
		Reason      string            `json:"reason"`
		Obligations map[string]any    `json:"obligations"`
		Headers     map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(outBuf, &out); err != nil {
		return w.fallbackDecision(), nil
	}
	return &Decision{
		Allow:       out.Allow,
		StatusCode:  out.StatusCode,
		Reason:      out.Reason,
		Obligations: out.Obligations,
		Headers:     out.Headers,
	}, nil
}

func (w *WASMRuntime) fallbackDecision() *Decision {
	if w.fallback.Allow {
		return &Decision{Allow: true, StatusCode: 200}
	}
	return &Decision{Allow: false, StatusCode: 503, Reason: "policy unavailable"}
}

// Loaded returns true if a policy bundle is currently loaded.
func (w *WASMRuntime) Loaded() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.module != nil
}

// BundlePath returns the path from which the current bundle was loaded, or empty if none or not loaded from file.
func (w *WASMRuntime) BundlePath() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.bundlePath
}
