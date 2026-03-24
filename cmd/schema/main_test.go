package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSchemasWritesFiles(t *testing.T) {
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	if err := generateSchemas(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auth.schema.json", "proxy.schema.json"} {
		p := filepath.Join("schemas", name)
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}
