package contract

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/accessgate/accessgate/internal/plugin"
)

// manifestsRoot returns the absolute path to configs/plugins/manifests if it exists.
func manifestsRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "configs", "plugins", "manifests")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("configs/plugins/manifests not found (run from repo root)")
	return ""
}

// TestExampleManifestsAreValid loads every JSON manifest shipped under
// configs/plugins/manifests through the real discovery + validation path. It guards against
// example manifests drifting out of sync with the validation rules (required fields, known
// kind, well-formed capabilities/depends_on). It also asserts dependency-graph assembly
// succeeds for the example set so depends_on references resolve to a provider.
func TestExampleManifestsAreValid(t *testing.T) {
	root := manifestsRoot(t)

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read manifests dir: %v", err)
	}
	var manifestCount int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		manifestCount++
	}
	if manifestCount == 0 {
		t.Skip("no example manifests to validate")
	}

	reg := plugin.New()
	if err := plugin.DiscoverFromDir(context.Background(), reg, root, nil); err != nil {
		t.Fatalf("discovery of example manifests failed: %v", err)
	}
	if err := reg.BuildDependencyGraph(); err != nil {
		t.Fatalf("dependency graph for example manifests failed: %v", err)
	}
	if got := len(reg.AllPluginIDs()); got != manifestCount {
		t.Fatalf("expected %d registered manifests, got %d", manifestCount, got)
	}
}
