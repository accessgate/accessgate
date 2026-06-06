// renderconfig prints an example auth or proxy config with ApplyDefaults applied (JSON).
// Use for make render-config-example.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	authconfig "github.com/accessgate/accessgate/internal/auth/config"
	proxyconfig "github.com/accessgate/accessgate/internal/proxy/config"
)

func main() {
	binary := os.Getenv("BINARY")
	if binary == "" {
		binary = "auth"
	}
	binary, warn := normalizeBinary(binary)
	if warn != "" {
		fmt.Fprintf(os.Stderr, "render-config-example: %s\n", warn)
	}
	format := strings.ToLower(os.Getenv("FORMAT"))
	if format == "" {
		format = "json"
	}
	if format != "json" {
		fmt.Fprintf(os.Stderr, "FORMAT must be json (YAML example output removed; use configs/*.yaml templates)\n")
		os.Exit(2)
	}

	if err := run(binary); err != nil {
		fmt.Fprintf(os.Stderr, "render-config-example: %v\n", err)
		os.Exit(1)
	}
}

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

func run(binary string) error {
	switch binary {
	case "auth":
		var cfg authconfig.Config
		cfg.ApplyDefaults()
		return emitJSON(&cfg)
	case "proxy":
		var cfg proxyconfig.Config
		cfg.ApplyDefaults()
		return emitJSON(&cfg)
	default:
		return fmt.Errorf("unknown BINARY=%q (use auth or proxy)", binary)
	}
}

func emitJSON(cfg any) error {
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}
