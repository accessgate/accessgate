// Package configload wires the go-config pipeline (file + env) used by accessgate-auth and accessgate-proxy.
// See https://pkg.go.dev/github.com/ArmanAvanesyan/go-config for the underlying loader, sources, and parsers.
package configload

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
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

	// The env source delivers every value as a string. For string-slice config
	// fields (e.g. the CommaStrings type backing OIDC_SCOPES), an env value like
	// "openid,profile,email" therefore arrives as a bare string, which the
	// go-config decoder rejects ("expected slice ... got string") because its
	// decoder does not consult json.Unmarshaler. A pre-decode resolver splits
	// those specific keys into a JSON array so env-only list values load
	// correctly, while file-sourced arrays (already []any) are left untouched.
	loader := goconfig.New(goconfig.WithResolver(commaListResolver(commaListKeys(out))))

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

// commaListKeys reflects over the target struct and returns the set of top-level
// JSON keys whose field type is a slice of strings (e.g. the CommaStrings type).
// These are the keys that, when supplied via an env var, arrive as a single
// comma-separated string and must be split into a list before decoding. out must
// be a pointer to a struct; anything else yields an empty set (no-op resolver).
func commaListKeys(out any) map[string]struct{} {
	keys := map[string]struct{}{}
	if out == nil {
		return keys
	}
	t := reflect.TypeOf(out)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return keys
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		ft := f.Type
		if ft.Kind() != reflect.Slice || ft.Elem().Kind() != reflect.String {
			continue
		}
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		keys[strings.ToLower(name)] = struct{}{}
	}
	return keys
}

// commaListResolver returns a resolver that, for each top-level tree key in keys
// whose merged value is a plain string, splits it on commas into a []any. This
// runs after merge and before decode, so it only ever sees the final value for a
// key: a file-sourced array stays a slice (untouched), while an env-sourced
// comma string becomes a list the decoder accepts. Empty/whitespace-only entries
// are dropped to match the file-path CommaStrings semantics (splitTrim).
func commaListResolver(keys map[string]struct{}) commaResolver {
	return commaResolver{keys: keys}
}

type commaResolver struct {
	keys map[string]struct{}
}

func (r commaResolver) Resolve(_ context.Context, tree map[string]any) (map[string]any, error) {
	if len(r.keys) == 0 || tree == nil {
		return tree, nil
	}
	for k, v := range tree {
		if _, ok := r.keys[strings.ToLower(k)]; !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		parts := strings.Split(s, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				out = append(out, t)
			}
		}
		tree[k] = out
	}
	return tree, nil
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
