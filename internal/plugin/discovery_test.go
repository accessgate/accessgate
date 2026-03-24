package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFromDirEmpty(t *testing.T) {
	reg := New()
	dir := t.TempDir()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverFromDirLoadsJSONManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	manifest := `{"id":"test.plugin","kind":"pipeline","name":"T","version":"1","capabilities":["pipeline:x"]}`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := New()
	if err := DiscoverFromDir(context.Background(), reg, dir, nil); err != nil {
		t.Fatal(err)
	}
	regd, ok := reg.RegistrationFor(PluginID("test.plugin"))
	if !ok || regd.Descriptor.ID != "test.plugin" {
		t.Fatalf("registration missing: ok=%v", ok)
	}
}
