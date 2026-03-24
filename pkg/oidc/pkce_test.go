package oidc

import "testing"

func TestGeneratePKCERoundTripLength(t *testing.T) {
	v, ch, n, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if v == "" || ch == "" || n == "" {
		t.Fatal("empty components")
	}
}

func TestGenerateState(t *testing.T) {
	s, err := GenerateState()
	if err != nil || s == "" {
		t.Fatalf("%q %v", s, err)
	}
}
