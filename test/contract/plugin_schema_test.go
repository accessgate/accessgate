// Package contract holds contract tests (e.g. plugin configs vs schemas).
package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmanAvanesyan/accessgate/internal/plugin"
	"github.com/xeipuuv/gojsonschema"
)

// gojsonschemaValidator implements plugin.JSONSchemaValidator using gojsonschema.
type gojsonschemaValidator struct{}

func (gojsonschemaValidator) Validate(schemaPath string, data map[string]any) error {
	schemaAbs, err := filepath.Abs(schemaPath)
	if err != nil {
		return err
	}
	// file:// URI: use forward slashes; Windows needs file:///C:/path
	schemaURL := "file:///" + filepath.ToSlash(schemaAbs)
	schemaLoader := gojsonschema.NewReferenceLoader(schemaURL)
	docBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	documentLoader := gojsonschema.NewBytesLoader(docBytes)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}
	if !result.Valid() {
		var errs string
		for _, e := range result.Errors() {
			if errs != "" {
				errs += "; "
			}
			errs += e.String()
		}
		return &validationError{msg: errs}
	}
	return nil
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

// pluginSchemaRoot returns the absolute path to schemas/plugins (repo root relative).
func pluginSchemaRoot(t *testing.T) string {
	t.Helper()
	// From test/contract go up to repo root then schemas/plugins
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// When running from repo root, "test/contract" is the package dir
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "schemas", "plugins")); err == nil {
			return filepath.Join(dir, "schemas", "plugins")
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("schemas/plugins not found (generate or check out schemas; run from repo root)")
	return ""
}

// configPluginsRoot returns the absolute path to configs/plugins.
func configPluginsRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "configs", "plugins")); err == nil {
			return filepath.Join(dir, "configs", "plugins")
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("configs/plugins not found (run from repo root)")
	return ""
}

// TestPluginConfigExamplesValidateAgainstSchemas ensures each plugin example config
// in configs/plugins that has a corresponding schema in schemas/plugins validates.
func TestPluginConfigExamplesValidateAgainstSchemas(t *testing.T) {
	schemaRoot := pluginSchemaRoot(t)
	configRoot := configPluginsRoot(t)
	resolver := &plugin.FilesystemSchemaResolver{Root: schemaRoot}
	validator := gojsonschemaValidator{}

	tests := []struct {
		name       string
		schemaRef  string
		configFile string
	}{
		{"caddy", "integration/caddy", "caddy.example.json"},
		{"krakend", "integration/krakend", "krakend.example.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(configRoot, tt.configFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("config file not found: %v", err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("parse config: %v", err)
			}
			env := plugin.Envelope{
				SchemaRef: tt.schemaRef,
				Raw:       raw,
			}
			if err := plugin.ValidateAgainstSchema(env, resolver, validator); err != nil {
				t.Errorf("ValidateAgainstSchema: %v", err)
			}
		})
	}
}
