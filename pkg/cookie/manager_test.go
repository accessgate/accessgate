package cookie

import "testing"

// SignedManager implements Manager.
var _ Manager = (*SignedManager)(nil)

func TestSignedManagerEncodeNonString(t *testing.T) {
	m := NewSignedManager("s")
	v, err := m.Encode(42)
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Fatalf("expected empty for non-string, got %q", v)
	}
}
