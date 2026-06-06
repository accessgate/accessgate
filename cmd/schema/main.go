package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	schemagen "github.com/ArmanAvanesyan/go-config/extensions/schema/generate"
	authconfig "github.com/accessgate/accessgate/internal/auth/config"
	proxyconfig "github.com/accessgate/accessgate/internal/proxy/config"
)

func main() {
	if err := generateSchemas(); err != nil {
		fmt.Fprintf(os.Stderr, "schema generation failed: %v\n", err)
		os.Exit(1)
	}
}

func generateSchemas() error {
	const dir = "schemas"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create schemas dir: %w", err)
	}

	authBytes, err := schemagen.GenerateFor[authconfig.Config](schemagen.WithTitle("AccessGate auth (OIDC/session) config"))
	if err != nil {
		return fmt.Errorf("generate schema for auth config: %w", err)
	}
	authBytes, err = boundSchema(authBytes)
	if err != nil {
		return fmt.Errorf("bound auth schema: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.schema.json"), authBytes, 0o644); err != nil {
		return fmt.Errorf("write auth.schema.json: %w", err)
	}

	proxyBytes, err := schemagen.GenerateFor[proxyconfig.Config](schemagen.WithTitle("AccessGate proxy config"))
	if err != nil {
		return fmt.Errorf("generate schema for proxy config: %w", err)
	}
	proxyBytes, err = boundSchema(proxyBytes)
	if err != nil {
		return fmt.Errorf("bound proxy schema: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.schema.json"), proxyBytes, 0o644); err != nil {
		return fmt.Errorf("write proxy.schema.json: %w", err)
	}

	return nil
}

func boundSchema(schemaBytes []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(schemaBytes, &v); err != nil {
		return nil, err
	}
	boundSchemaValue(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}

func boundSchemaValue(v any) {
	switch node := v.(type) {
	case map[string]any:
		typeName, _ := node["type"].(string)
		if typeName == "object" {
			if _, hasAdditional := node["additionalProperties"]; !hasAdditional {
				node["additionalProperties"] = false
			}
		}
		for _, child := range node {
			boundSchemaValue(child)
		}
	case []any:
		for _, child := range node {
			boundSchemaValue(child)
		}
	}
}
