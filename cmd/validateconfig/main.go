// validateconfig loads an auth or proxy config file and runs the same validation
// as the runtime (file + env merge, ApplyDefaults + Validate). Use for make validate-config.
//
// Environment variables override file values (same as cmd/accessgate-auth and cmd/accessgate-proxy).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	authconfig "github.com/accessgate/accessgate/internal/auth/config"
	proxyconfig "github.com/accessgate/accessgate/internal/proxy/config"
	"github.com/xeipuuv/gojsonschema"
	"sigs.k8s.io/yaml"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = os.Getenv("AUTH_CONFIG")
	}
	if configPath == "" {
		configPath = os.Getenv("AGENT_CONFIG")
	}
	if configPath == "" {
		configPath = os.Getenv("PROXY_CONFIG")
	}
	binary := os.Getenv("BINARY")
	if binary == "" && configPath != "" {
		if strings.Contains(configPath, "proxy") {
			binary = "proxy"
		} else {
			binary = "auth"
		}
	}
	if binary == "" {
		binary = "auth"
	}
	binary, warn := normalizeBinary(binary)
	if warn != "" {
		fmt.Fprintf(os.Stderr, "validate-config: %s\n", warn)
	}

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "usage: CONFIG_PATH=/path/to/config.json BINARY=auth|proxy %s\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  or set AUTH_CONFIG (or deprecated AGENT_CONFIG) / PROXY_CONFIG instead of CONFIG_PATH\n")
		os.Exit(2)
	}

	if err := run(configPath, binary); err != nil {
		fmt.Fprintf(os.Stderr, "validate-config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("config valid")
}

// normalizeBinary maps legacy "agent" to "auth" and returns a deprecation warning if so.
func normalizeBinary(s string) (string, string) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "agent":
		return "auth", `BINARY=agent is deprecated; use BINARY=auth`
	case "auth", "proxy":
		return s, ""
	default:
		return s, ""
	}
}

func run(configPath, binary string) error {
	if err := validateAgainstSchema(configPath, binary); err != nil {
		return err
	}

	ctx := context.Background()
	switch binary {
	case "auth":
		_, err := authconfig.Load(ctx, configPath)
		return err
	case "proxy":
		_, err := proxyconfig.Load(ctx, configPath)
		return err
	default:
		return fmt.Errorf("unknown BINARY=%q (use auth or proxy)", binary)
	}
}

func validateAgainstSchema(configPath, binary string) error {
	schemaPath, err := findSchemaPath(binary)
	if err != nil {
		return err
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config for schema validation: %w", err)
	}

	jsonBytes, err := yaml.YAMLToJSON(configBytes)
	if err != nil {
		return fmt.Errorf("parse config as json/yaml: %w", err)
	}

	var doc any
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return fmt.Errorf("decode config json: %w", err)
	}

	result, err := gojsonschema.Validate(gojsonschema.NewReferenceLoader("file://"+mustAbs(schemaPath)), gojsonschema.NewGoLoader(doc))
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	if result.Valid() {
		return nil
	}

	msgs := make([]string, 0, len(result.Errors()))
	for _, e := range result.Errors() {
		msgs = append(msgs, e.String())
	}
	return fmt.Errorf("schema validation errors: %s", strings.Join(msgs, "; "))
}

func findSchemaPath(binary string) (string, error) {
	name := binary + ".schema.json"

	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; dir = filepath.Dir(dir) {
			candidate := filepath.Join(dir, "schemas", name)
			if _, statErr := os.Stat(candidate); statErr == nil {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}

	return "", fmt.Errorf("schema not found for %q (expected schemas/%s)", binary, name)
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
