// validateconfig loads an auth or proxy config file and runs the same validation
// as the runtime (file + env merge, ApplyDefaults + Validate). Use for make validate-config.
//
// Environment variables override file values (same as cmd/accessgate-auth and cmd/accessgate-proxy).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	authconfig "github.com/ArmanAvanesyan/accessgate/internal/auth/config"
	proxyconfig "github.com/ArmanAvanesyan/accessgate/internal/proxy/config"
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
