package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Envelope is the common wrapper for plugin configuration.
// It is designed to be embedded or referenced from internal/*/config types
// that are populated via go-config.
type Envelope struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Type    string `json:"type"`
	Version string `json:"version"`

	SchemaRef string `json:"schema_ref"`
	Enabled   bool   `json:"enabled"`

	// Raw holds the untyped plugin-specific configuration as a JSON object.
	Raw map[string]any `json:"raw"`
}

// SchemaResolver resolves schema references to absolute file paths.
type SchemaResolver interface {
	Resolve(ref string) (string, error)
}

// FilesystemSchemaResolver resolves refs to files under a schemas/plugins/ root.
type FilesystemSchemaResolver struct {
	Root string
}

// Resolve maps a logical schema ref (e.g. "plugins/provider/oidc") to a JSON schema file path.
func (r *FilesystemSchemaResolver) Resolve(ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("plugin: empty schema ref")
	}
	path := filepath.Join(r.Root, ref+".schema.json")
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

// JSONSchemaValidator validates an envelope's Raw config against a JSON Schema.
// Implementations can be wired in tests or tooling; the runtime does not depend
// on any particular JSON Schema library.
type JSONSchemaValidator interface {
	Validate(schemaPath string, data map[string]any) error
}

// ValidateAgainstSchema resolves the schema reference and validates the envelope's Raw config.
// This is intended for tooling or startup validation, not the hot path.
func ValidateAgainstSchema(env Envelope, resolver SchemaResolver, validator JSONSchemaValidator) error {
	if env.SchemaRef == "" {
		return nil
	}
	if resolver == nil || validator == nil {
		return nil
	}
	schemaPath, err := resolver.Resolve(env.SchemaRef)
	if err != nil {
		return fmt.Errorf("plugin: resolve schema %q: %w", env.SchemaRef, err)
	}
	if err := validator.Validate(schemaPath, env.Raw); err != nil {
		return fmt.Errorf("plugin: validate schema %q: %w", env.SchemaRef, err)
	}
	return nil
}

// DecodeRaw decodes the Raw map into the provided struct pointer.
func DecodeRaw(env Envelope, out any) error {
	if env.Raw == nil {
		return nil
	}
	buf, err := json.Marshal(env.Raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}
