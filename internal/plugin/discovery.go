package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Manifest describes a plugin instance discovered from the filesystem.
type Manifest struct {
	ID              string             `json:"id" yaml:"id"`
	Kind            string             `json:"kind" yaml:"kind"`
	Name            string             `json:"name" yaml:"name"`
	Description     string             `json:"description" yaml:"description"`
	Version         string             `json:"version" yaml:"version"`
	Capabilities    []string           `json:"capabilities" yaml:"capabilities"`
	DependsOn       []string           `json:"depends_on" yaml:"depends_on"`
	ConfigSchemaRef string             `json:"config_schema_ref" yaml:"config_schema_ref"`
	Enabled         *bool              `json:"enabled" yaml:"enabled"`
	Metadata        map[string]any     `json:"metadata" yaml:"metadata"`
	Signature       *ManifestSignature `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// ManifestSignature holds optional integrity information for a manifest or its payload.
type ManifestSignature struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Value     string `json:"value" yaml:"value"`
}

// Verifier validates manifest signatures or checksums when present.
type Verifier interface {
	Verify(manifestPath string, m *Manifest) error
}

// BuiltinRegistrar is implemented by packages that register built-in plugins.
// Hosts can call this during startup to ensure built-ins are registered before discovery.
type BuiltinRegistrar interface {
	RegisterBuiltins(ctx context.Context, reg *Registry) error
}

// DiscoverFromDir walks the given root and attempts to load plugin manifests from matching files.
// v1 implementation expects JSON manifests; YAML can be added later if desired.
func DiscoverFromDir(ctx context.Context, reg *Registry, root string, verifier Verifier) error {
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".json" {
			return nil
		}
		if err := discoverSingle(ctx, reg, path, verifier); err != nil {
			return fmt.Errorf("plugin: %w", err)
		}
		return nil
	})
	if os.IsNotExist(err) {
		// No discovery directory configured; treat as no plugins.
		return nil
	}
	return err
}

func discoverSingle(ctx context.Context, reg *Registry, path string, verifier Verifier) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal manifest %s: %w", path, err)
	}
	if err := validateManifest(path, &m); err != nil {
		return err
	}
	if verifier != nil {
		if err := verifier.Verify(path, &m); err != nil {
			return fmt.Errorf("verify manifest %s: %w", path, err)
		}
	}

	desc, err := toDescriptor(&m)
	if err != nil {
		return fmt.Errorf("manifest %s: %w", path, err)
	}

	// In v1, manifest-based plugins refer to already-linked implementations.
	// The factory is expected to be provided by the host; here we register a no-op
	// factory placeholder which can be replaced by host code if desired.
	factory := func(ctx context.Context, d PluginDescriptor) (Plugin, error) {
		return nil, fmt.Errorf("plugin: factory not provided for plugin %s", d.ID)
	}

	if err := reg.Register(desc, factory); err != nil {
		return err
	}
	if m.Enabled != nil && !*m.Enabled {
		_ = reg.Disable(desc.ID)
	}
	return nil
}

// knownKind reports whether kind is a recognized plugin kind.
func knownKind(kind PluginKind) bool {
	switch kind {
	case PluginKindPipeline, PluginKindProvider, PluginKindIntegration:
		return true
	default:
		return false
	}
}

// validateManifest enforces structural requirements on a discovered manifest before it is
// registered: required fields (id, kind, capabilities), a known kind, and well-formed
// capability/depends_on entries. Errors include the manifest path and id for actionability.
// Cross-manifest dependency resolution (depends_on -> a capability provider) is enforced
// later by Registry.BuildDependencyGraph; here we only validate that the references are
// syntactically present and non-empty.
func validateManifest(path string, m *Manifest) error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("plugin: manifest %s: missing required field %q", path, "id")
	}
	if strings.TrimSpace(m.Kind) == "" {
		return fmt.Errorf("plugin: manifest %s (id=%q): missing required field %q", path, m.ID, "kind")
	}
	if !knownKind(PluginKind(m.Kind)) {
		return fmt.Errorf("plugin: manifest %s (id=%q): unknown kind %q (want one of %q, %q, %q)",
			path, m.ID, m.Kind, PluginKindPipeline, PluginKindProvider, PluginKindIntegration)
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("plugin: manifest %s (id=%q): missing required field %q", path, m.ID, "capabilities")
	}
	for i, c := range m.Capabilities {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("plugin: manifest %s (id=%q): empty capability at index %d", path, m.ID, i)
		}
	}
	for i, d := range m.DependsOn {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("plugin: manifest %s (id=%q): empty depends_on entry at index %d", path, m.ID, i)
		}
	}
	return nil
}

func toDescriptor(m *Manifest) (PluginDescriptor, error) {
	kind := PluginKind(m.Kind)
	if !knownKind(kind) {
		return PluginDescriptor{}, fmt.Errorf("unknown plugin kind %q", m.Kind)
	}
	caps := make([]Capability, len(m.Capabilities))
	for i, c := range m.Capabilities {
		caps[i] = Capability(c)
	}
	depCaps := make([]Capability, len(m.DependsOn))
	for i, c := range m.DependsOn {
		depCaps[i] = Capability(c)
	}
	return PluginDescriptor{
		ID:              PluginID(m.ID),
		Kind:            kind,
		Name:            m.Name,
		Description:     m.Description,
		Version:         m.Version,
		Capabilities:    caps,
		DependsOn:       depCaps,
		ConfigSchemaRef: m.ConfigSchemaRef,
		VersionInfo: VersionInfo{
			APIVersion:        "",
			MinRuntimeVersion: "",
			MaxRuntimeVersion: "",
		},
	}, nil
}
