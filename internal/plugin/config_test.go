package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemSchemaResolverEmptyRef(t *testing.T) {
	r := FilesystemSchemaResolver{Root: t.TempDir()}
	_, err := r.Resolve("")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFilesystemSchemaResolverResolve(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "my.schema.json")
	if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := FilesystemSchemaResolver{Root: dir}
	got, err := r.Resolve("my")
	if err != nil || got != p {
		t.Fatalf("%q %v", got, err)
	}
}

func TestValidateAgainstSchemaNoRef(t *testing.T) {
	if err := ValidateAgainstSchema(Envelope{}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRawNil(t *testing.T) {
	if err := DecodeRaw(Envelope{}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
}
