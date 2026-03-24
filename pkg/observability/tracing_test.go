package observability

import (
	"context"
	"testing"
)

var _ Tracer = NopTracer{}

func TestNopTracerStartSpan(t *testing.T) {
	var tr NopTracer
	ctx := context.Background()
	ctx2, sp := tr.StartSpan(ctx, "op", "k", "v")
	if ctx2 == nil || sp == nil {
		t.Fatal("unexpected nil")
	}
	sp.End()
}
