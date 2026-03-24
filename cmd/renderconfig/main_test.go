package main

import "testing"

func TestNormalizeBinaryRender(t *testing.T) {
	b, w := normalizeBinary("agent")
	if b != "auth" || w == "" {
		t.Fatalf("%q %q", b, w)
	}
}

func TestRunUnknownBinary(t *testing.T) {
	if err := run("nope"); err == nil {
		t.Fatal("expected error")
	}
}
