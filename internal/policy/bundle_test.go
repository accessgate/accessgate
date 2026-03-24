package policy

import (
	"path/filepath"
	"testing"
)

func TestBundleLoaderMissingFile(t *testing.T) {
	b := NewBundleLoader(DefaultFallbackDeny, "")
	_, err := b.LoadBundle(filepath.Join(t.TempDir(), "missing.wasm"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
