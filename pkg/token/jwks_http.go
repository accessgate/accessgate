package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxJWKSBytes = 512 * 1024 // 512 KB

// Metrics captures optional JWKS cache metrics. It is intentionally a minimal,
// consumer-defined interface so that pkg/token does not depend on pkg/observability;
// observability.Metrics (a superset) structurally satisfies it. Callers that have an
// observability.Metrics can pass it directly to NewHTTPJWKSSource.
type Metrics interface {
	JWKSCacheHit(issuer string)
	JWKSCacheMiss(issuer string)
}

// nopMetrics is a no-op Metrics implementation used internally when no metrics
// sink is supplied. External callers pass their own Metrics (or nil) — there is
// no need to expose a no-op impl here, so it is unexported.
type nopMetrics struct{}

func (nopMetrics) JWKSCacheHit(string)  {}
func (nopMetrics) JWKSCacheMiss(string) {}

// HTTPJWKSSource fetches JWKS from the OIDC issuer (via discovery) with an in-memory cache.
type HTTPJWKSSource struct {
	client  *http.Client
	cache   map[string]jwkSEntry
	mu      sync.Mutex
	ttl     time.Duration
	metrics Metrics
}

type jwkSEntry struct {
	data []byte
	exp  time.Time
}

type discoveryResponse struct {
	JWKSURI string `json:"jwks_uri"`
}

// NewHTTPJWKSSource creates an HTTP JWKS source with the given cache TTL.
func NewHTTPJWKSSource(cacheTTL time.Duration, metrics Metrics) *HTTPJWKSSource {
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}
	if metrics == nil {
		metrics = nopMetrics{}
	}
	return &HTTPJWKSSource{
		client:  &http.Client{Timeout: 10 * time.Second},
		cache:   make(map[string]jwkSEntry),
		ttl:     cacheTTL,
		metrics: metrics,
	}
}

func (s *HTTPJWKSSource) GetJWKS(ctx context.Context, issuer string) ([]byte, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.cache[issuer]; ok && time.Now().Before(e.exp) {
		s.metrics.JWKSCacheHit(issuer)
		return e.data, nil
	}
	s.metrics.JWKSCacheMiss(issuer)
	jwksURI, err := s.fetchJWKSURI(ctx, issuer)
	if err != nil {
		return nil, err
	}
	data, err := s.fetchURL(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	s.cache[issuer] = jwkSEntry{data: data, exp: time.Now().Add(s.ttl)}
	return data, nil
}

func (s *HTTPJWKSSource) fetchJWKSURI(ctx context.Context, issuer string) (string, error) {
	url := issuer + "/.well-known/openid-configuration"
	data, err := s.fetchURL(ctx, url)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	var dr discoveryResponse
	if err := json.Unmarshal(data, &dr); err != nil {
		return "", fmt.Errorf("oidc discovery parse: %w", err)
	}
	if dr.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery: missing jwks_uri")
	}
	return dr.JWKSURI, nil
}

func (s *HTTPJWKSSource) fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
}
