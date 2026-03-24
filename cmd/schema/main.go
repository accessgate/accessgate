package main

import (
	"fmt"
	"os"
	"path/filepath"

	authconfig "github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	proxyconfig "github.com/ArmanAvanesyan/accessgate/internal/proxy/config"
	schemagen "github.com/ArmanAvanesyan/go-config/extensions/schema/generate"
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
	if err := os.WriteFile(filepath.Join(dir, "auth.schema.json"), authBytes, 0o644); err != nil {
		return fmt.Errorf("write auth.schema.json: %w", err)
	}

	proxyBytes, err := schemagen.GenerateFor[proxyconfig.Config](schemagen.WithTitle("AccessGate proxy config"))
	if err != nil {
		return fmt.Errorf("generate schema for proxy config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.schema.json"), proxyBytes, 0o644); err != nil {
		return fmt.Errorf("write proxy.schema.json: %w", err)
	}

	return nil
}
