package testutil

import "testing"

func TestNewTestPrincipal(t *testing.T) {
	p := NewTestPrincipal("sub-1")
	if p == nil || p.Subject != "sub-1" || p.ExpiresAt.IsZero() {
		t.Fatalf("%+v", p)
	}
}

func TestNewTestJWT(t *testing.T) {
	if got := NewTestJWT("u"); got != "test-jwt-for-u" {
		t.Fatal(got)
	}
}
