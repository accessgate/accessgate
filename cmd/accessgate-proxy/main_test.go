package main

import (
	"context"
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
	e, err := buildPolicyEngine(cfg)
	if err != nil || e == nil {
		t.Fatalf("%v %v", e, err)
	}
}

func TestBuildPipelinePluginsEmpty(t *testing.T) {
	cfg := &config.Config{}
	pl, err := buildPipelinePlugins(context.Background(), cfg, plugin.New())
	if err != nil || pl != nil {
		t.Fatalf("%v %v", pl, err)
	}
}
