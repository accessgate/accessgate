package plugin

import "testing"

func TestPluginKindConstants(t *testing.T) {
	if PluginKindPipeline != "pipeline" || PluginKindProvider != "provider" {
		t.Fatal("unexpected kind constants")
	}
}

func TestPluginStateConstants(t *testing.T) {
	if PluginStateHealthy != "healthy" {
		t.Fatal(PluginStateHealthy)
	}
}
