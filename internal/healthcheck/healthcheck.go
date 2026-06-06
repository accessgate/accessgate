// Package healthcheck provides a tiny, dependency-free HTTP liveness probe
// used as the in-container Docker HEALTHCHECK for the AccessGate binaries.
//
// The distroless/static base image used for the release images
// (see build/docker/Dockerfile.*) has no shell and no curl/wget, so the
// HEALTHCHECK cannot shell out. Instead each binary exposes a "healthcheck"
// subcommand that performs a single HTTP GET against its own /healthz endpoint
// on 127.0.0.1 and exits 0 (healthy) or 1 (unhealthy).
package healthcheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Run performs a single GET http://127.0.0.1:<port><path> and returns nil when
// the response status is 2xx. The port is resolved from the provided
// environment variable (portEnv), falling back to defaultPort when unset/empty.
//
// It is intentionally self-contained: no config loading, no external
// dependencies, so it works inside a minimal distroless container.
func Run(portEnv, defaultPort, path string) error {
	port := os.Getenv(portEnv)
	if port == "" {
		port = defaultPort
	}

	url := fmt.Sprintf("http://127.0.0.1:%s%s", port, path)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck GET %s: %w", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("healthcheck GET %s: unhealthy status %d", url, resp.StatusCode)
	}
	return nil
}
