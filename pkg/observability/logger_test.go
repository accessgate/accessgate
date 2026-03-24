package observability

import "testing"

var _ Logger = NopLogger{}

func TestNopLoggerWithChain(t *testing.T) {
	var l Logger = NopLogger{}
	l.Info("a", "k", "v")
	l2 := l.With("x", 1)
	l2.Warn("w")
}
