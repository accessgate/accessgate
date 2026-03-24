// Package configload wires the go-config pipeline (file + env) used by accessgate-auth and accessgate-proxy.
// See https://pkg.go.dev/github.com/ArmanAvanesyan/go-config for the underlying loader, sources, and parsers.
package configload

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	goconfig "github.com/ArmanAvanesyan/go-config/config"
	jsonparser "github.com/ArmanAvanesyan/go-config/providers/parser/json"
	yamlparser "github.com/ArmanAvanesyan/go-config/providers/parser/yaml"
	"github.com/ArmanAvanesyan/go-config/providers/source/env"
	"github.com/ArmanAvanesyan/go-config/providers/source/file"
)

// LoadInto merges optional file (JSON or YAML) with all environment variables, then decodes into out.
// Later sources win: env overrides file. out must be a non-nil pointer to a struct with json tags.
func LoadInto(ctx context.Context, configPath string, out any) error {
	if out == nil {
		return fmt.Errorf("config target is nil")
	}

	loader := goconfig.New()

	var closeParser func() error
	if configPath != "" {
		p, closeFn, err := parserForPath(ctx, configPath)
		if err != nil {
			return err
		}
		closeParser = closeFn
		loader.AddSource(file.New(configPath), p)
	}
	loader.AddSource(env.New(""))

	if closeParser != nil {
		defer func() { _ = closeParser() }()
	}

	if err := loader.Load(ctx, out); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return nil
}

func parserForPath(ctx context.Context, configPath string) (goconfig.Parser, func() error, error) {
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		p, err := yamlparser.New(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("create yaml parser: %w", err)
		}
		return p, func() error { return p.Close(ctx) }, nil
	default:
		return jsonparser.New(), nil, nil
	}
}
