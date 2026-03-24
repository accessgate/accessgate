package configload

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// String-only fields avoid flaky merges when the process environment contains
// unrelated vars that map to common names (e.g. BAR) with non-numeric values.
type testConfig struct {
	Foo string `json:"foo"`
	Bar string `json:"bar"`
}

func TestLoadIntoNilOut(t *testing.T) {
	err := LoadInto(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error for nil out")
	}
}

func TestLoadIntoJSONFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(p, []byte(`{"foo":"a","bar":"2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out testConfig
	if err := LoadInto(context.Background(), p, &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	if out.Foo != "a" || out.Bar != "2" {
		t.Fatalf("got %+v, want foo=a bar=2", out)
	}
}

func TestLoadIntoYAMLFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, []byte("foo: y\nbar: \"5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out testConfig
	if err := LoadInto(context.Background(), p, &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	if out.Foo != "y" || out.Bar != "5" {
		t.Fatalf("got %+v, want foo=y bar=5", out)
	}
}

func TestLoadIntoEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(p, []byte(`{"foo":"fromfile","bar":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FOO", "fromenv")
	t.Setenv("BAR", "99")
	var out testConfig
	if err := LoadInto(context.Background(), p, &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	if out.Foo != "fromenv" || out.Bar != "99" {
		t.Fatalf("got %+v, want env override", out)
	}
}

func TestLoadIntoEnvOnly(t *testing.T) {
	t.Setenv("FOO", "only")
	t.Setenv("BAR", "7")
	var out testConfig
	if err := LoadInto(context.Background(), "", &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	if out.Foo != "only" || out.Bar != "7" {
		t.Fatalf("got %+v", out)
	}
}

func TestLoadIntoMissingFile(t *testing.T) {
	err := LoadInto(context.Background(), filepath.Join(t.TempDir(), "nope.json"), &testConfig{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
