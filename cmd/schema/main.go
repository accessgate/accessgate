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
	authBytes, err = relaxNested(authBytes, map[string][]string{
		// Only these connector fields are required; the rest are defaulted by Config.Normalize.
		"connectors": {"id", "oidc_issuer", "oidc_redirect_uri", "oidc_client_id"},
	}, []string{"claim_mapping"})
	if err != nil {
		return fmt.Errorf("relax auth schema: %w", err)
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
	proxyBytes, err = relaxNested(proxyBytes, map[string][]string{
		// Only these route fields are required; the rest are defaulted by Config.Normalize.
		"routes": {"id", "path_prefix", "upstream_url"},
	}, nil)
	if err != nil {
		return fmt.Errorf("relax proxy schema: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.schema.json"), proxyBytes, 0o644); err != nil {
		return fmt.Errorf("write proxy.schema.json: %w", err)
	}

	return nil
}

// relaxNested rewrites the "required" list of array-of-object properties to reflect the runtime
// contract: nested connector/route items default most fields via Config.Normalize, so only the
// genuinely-required fields should be required in the schema. requiredByProp maps a top-level
// array property name to its item's required field set; fullyOptional names item sub-objects
// (e.g. claim_mapping) whose every field is optional (required emptied).
func relaxNested(schemaBytes []byte, requiredByProp map[string][]string, fullyOptional []string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(schemaBytes, &doc); err != nil {
		return nil, err
	}
	props, _ := doc["properties"].(map[string]any)
	for prop, required := range requiredByProp {
		arr, ok := props[prop].(map[string]any)
		if !ok {
			continue
		}
		items, ok := arr["items"].(map[string]any)
		if !ok {
			continue
		}
		req := make([]any, 0, len(required))
		for _, r := range required {
			req = append(req, r)
		}
		items["required"] = req
		itemProps, _ := items["properties"].(map[string]any)
		for _, name := range fullyOptional {
			if sub, ok := itemProps[name].(map[string]any); ok {
				sub["required"] = []any{}
			}
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
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

// optionalTopLevelFields are the only config keys that may be omitted. They preserve
// backward compatibility: when absent, the runtime synthesizes a single connector/route
// from the legacy singular fields (see Config.Normalize in each config package). The
// generator otherwise marks every field required, so we prune these from "required".
var optionalTopLevelFields = map[string]bool{
	"connectors": true,
	"routes":     true,
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
		if req, ok := node["required"].([]any); ok {
			pruned := req[:0]
			for _, name := range req {
				if s, ok := name.(string); ok && optionalTopLevelFields[s] {
					continue
				}
				pruned = append(pruned, name)
			}
			node["required"] = pruned
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
