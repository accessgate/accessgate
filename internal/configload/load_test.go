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

// commaConfig exercises the comma-separated list handling for string-slice
// fields (the CommaStrings shape). The env source delivers values as strings;
// LoadInto must split a comma string into a list for these fields.
type commaConfig struct {
	Foo  string   `json:"foo"`
	List []string `json:"oidc_scopes"`
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestLoadIntoCommaListEnvOnly is the v1.0 config-freeze round-trip guard
// (#103, COMPATIBILITY.md §1): a comma-separated env value for a string-slice
// field must load WITHOUT any config file present. go-config's decoder rejects a
// bare string for a slice field and does not consult json.Unmarshaler, so
// LoadInto splits these keys before decode. This is the env-only list path.
func TestLoadIntoCommaListEnvOnly(t *testing.T) {
	t.Setenv("OIDC_SCOPES", "openid,profile,email")
	var out commaConfig
	if err := LoadInto(context.Background(), "", &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	want := []string{"openid", "profile", "email"}
	if !equalStrings(out.List, want) {
		t.Fatalf("comma env-only: got %#v, want %#v", out.List, want)
	}
}

// TestLoadIntoCommaListEnvSingle confirms a single env value (no commas) loads
// as a one-element list, and surrounding whitespace/empty entries are trimmed.
func TestLoadIntoCommaListEnvSingle(t *testing.T) {
	t.Setenv("OIDC_SCOPES", " openid ,, profile ,")
	var out commaConfig
	if err := LoadInto(context.Background(), "", &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	want := []string{"openid", "profile"}
	if !equalStrings(out.List, want) {
		t.Fatalf("comma trim: got %#v, want %#v", out.List, want)
	}
}

// TestLoadIntoCommaListFileArray confirms the file path is unaffected: a
// JSON/YAML array still decodes as a slice (the resolver only rewrites string
// values for these keys; arrays arrive as slices and are left untouched).
func TestLoadIntoCommaListFileArray(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(p, []byte(`{"oidc_scopes":["openid","groups"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out commaConfig
	if err := LoadInto(context.Background(), p, &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	want := []string{"openid", "groups"}
	if !equalStrings(out.List, want) {
		t.Fatalf("file array: got %#v, want %#v", out.List, want)
	}
}

// TestLoadIntoCommaListEnvOverridesFileArray confirms env (comma string) wins
// over a file array for a list field, matching the documented env-overrides-file
// precedence for every other key.
func TestLoadIntoCommaListEnvOverridesFileArray(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(p, []byte(`{"oidc_scopes":["fromfile"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIDC_SCOPES", "openid,profile")
	var out commaConfig
	if err := LoadInto(context.Background(), p, &out); err != nil {
		t.Fatalf("LoadInto: %v", err)
	}
	want := []string{"openid", "profile"}
	if !equalStrings(out.List, want) {
		t.Fatalf("env override array: got %#v, want %#v", out.List, want)
	}
}
