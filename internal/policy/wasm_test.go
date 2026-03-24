package policy

import (
	"context"
	"testing"
)

func TestWASMRuntimeFallbackNoModule(t *testing.T) {
	w := NewWASMRuntime(DefaultFallbackDeny)
	dec, err := w.Evaluate(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if dec.Allow || dec.StatusCode != 503 {
		t.Fatalf("expected fallback deny 503, got Allow=%v StatusCode=%d", dec.Allow, dec.StatusCode)
	}
	w2 := NewWASMRuntime(DefaultFallbackAllow)
	dec2, _ := w2.Evaluate(context.Background(), Input{})
	if !dec2.Allow || dec2.StatusCode != 200 {
		t.Fatalf("expected fallback allow 200, got Allow=%v StatusCode=%d", dec2.Allow, dec2.StatusCode)
	}
}
