package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/accessgate/accessgate/internal/plugin"
	"github.com/accessgate/accessgate/internal/proxy/config"
)

func TestBuildPolicyEngineWASMNoBundle(t *testing.T) {
	cfg := &config.Config{PolicyEngine: config.PolicyEngineWASM, PolicyBundlePath: ""}
	cfg.ApplyDefaults()
	cfg.AllowPrivateUpstreams = true
	cfg.UpstreamURL = "http://u"
	cfg.AuthURL = "http://a"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	e, stop, err := buildPolicyEngine(context.Background(), cfg)
	if err != nil || e == nil {
		t.Fatalf("%v %v", e, err)
	}
	if stop != nil {
		stop()
	}
}

func TestBuildPipelinePluginsEmpty(t *testing.T) {
	cfg := &config.Config{}
	pl, err := buildPipelinePlugins(context.Background(), cfg, plugin.New())
	if err != nil || pl != nil {
		t.Fatalf("%v %v", pl, err)
	}
}

func writeBadManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Missing required "capabilities" field -> validation error during discovery.
	contents := `{"id":"bad.plugin","kind":"pipeline"}`
	if err := os.WriteFile(filepath.Join(dir, "p.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDiscoverManifestsStrictFailsClosed(t *testing.T) {
	cfg := &config.Config{
		PluginsManifestDir:    writeBadManifest(t),
		PluginsManifestStrict: true,
	}
	reg := plugin.New()
	err := discoverManifests(context.Background(), cfg, reg)
	if err == nil {
		t.Fatal("expected strict discovery to fail on invalid manifest")
	}
}

func TestDiscoverManifestsNonStrictContinues(t *testing.T) {
	cfg := &config.Config{
		PluginsManifestDir:    writeBadManifest(t),
		PluginsManifestStrict: false,
	}
	reg := plugin.New()
	if err := discoverManifests(context.Background(), cfg, reg); err != nil {
		t.Fatalf("expected non-strict discovery to continue, got %v", err)
	}
	if len(reg.AllPluginIDs()) != 0 {
		t.Fatalf("invalid manifest should not have registered: %v", reg.AllPluginIDs())
	}
}

func TestDiscoverManifestsBadVerifierKeyFatal(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		PluginsManifestDir:           dir,
		PluginsManifestPublicKeyPath: keyPath,
		// Even non-strict: a bad verifier key is always fatal.
		PluginsManifestStrict: false,
	}
	reg := plugin.New()
	if err := discoverManifests(context.Background(), cfg, reg); err == nil {
		t.Fatal("expected fatal error for unparseable verifier key")
	}
}
