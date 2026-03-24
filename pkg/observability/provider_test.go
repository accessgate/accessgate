package observability

import "testing"

func TestNewProviderFillsNops(t *testing.T) {
	p := NewProvider(nil, nil, nil)
	if p == nil || p.Logger == nil || p.Metrics == nil || p.Tracer == nil {
		t.Fatal(p)
	}
}

func TestNewProviderPassthrough(t *testing.T) {
	l := NewStdLogger(nil)
	p := NewProvider(l, NopMetrics{}, NopTracer{})
	if p.Logger != l {
		t.Fatal("expected Logger to be passed through unchanged")
	}
}
