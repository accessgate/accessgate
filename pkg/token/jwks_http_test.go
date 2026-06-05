package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// jwksTestServer spins up an httptest server exposing a discovery document and
// a JWKS endpoint, counting hits on each. The discovery doc points at this
// server's own /jwks path.
type jwksTestServer struct {
	srv           *httptest.Server
	jwksBody      []byte
	discoveryHits int
	jwksHits      int
	mu            sync.Mutex
	// failDiscovery / failJWKS force non-200 responses when set.
	failDiscovery bool
	failJWKS      bool
	// jwksURIOverride, when non-empty, is used instead of the self URL.
	jwksURIOverride string
	// omitJWKSURI omits jwks_uri from the discovery document.
	omitJWKSURI bool
}

func newJWKSTestServer(t *testing.T, jwksBody []byte) *jwksTestServer {
	t.Helper()
	ts := &jwksTestServer{jwksBody: jwksBody}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			ts.mu.Lock()
			ts.discoveryHits++
			fail := ts.failDiscovery
			ts.mu.Unlock()
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			jwksURI := ts.srv.URL + "/jwks"
			if ts.jwksURIOverride != "" {
				jwksURI = ts.jwksURIOverride
			}
			doc := map[string]any{}
			if !ts.omitJWKSURI {
				doc["jwks_uri"] = jwksURI
			}
			_ = json.NewEncoder(w).Encode(doc)
		case r.URL.Path == "/jwks":
			ts.mu.Lock()
			ts.jwksHits++
			fail := ts.failJWKS
			body := ts.jwksBody
			ts.mu.Unlock()
			if fail {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *jwksTestServer) counts() (disc, jwks int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.discoveryHits, ts.jwksHits
}

// countingMetrics records cache hits/misses.
type countingMetrics struct {
	hits   int
	misses int
}

func (m *countingMetrics) JWKSCacheHit(string)  { m.hits++ }
func (m *countingMetrics) JWKSCacheMiss(string) { m.misses++ }

func TestHTTPJWKSSource_FetchAndCache(t *testing.T) {
	key := rsaTestKey(t)
	body := rsaJWKS(t, key, testKID)
	ts := newJWKSTestServer(t, body)

	metrics := &countingMetrics{}
	src := NewHTTPJWKSSource(time.Minute, metrics)
	ctx := context.Background()

	got, err := src.GetJWKS(ctx, ts.srv.URL)
	if err != nil {
		t.Fatalf("first GetJWKS: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("jwks body mismatch:\n got %s\nwant %s", got, body)
	}
	if disc, jwks := ts.counts(); disc != 1 || jwks != 1 {
		t.Fatalf("after first fetch: discovery=%d jwks=%d, want 1/1", disc, jwks)
	}
	if metrics.misses != 1 || metrics.hits != 0 {
		t.Fatalf("metrics after first fetch: hits=%d misses=%d", metrics.hits, metrics.misses)
	}

	// Second call within TTL must come from cache (no new HTTP hits).
	got2, err := src.GetJWKS(ctx, ts.srv.URL)
	if err != nil {
		t.Fatalf("second GetJWKS: %v", err)
	}
	if string(got2) != string(body) {
		t.Fatalf("cached jwks body mismatch")
	}
	if disc, jwks := ts.counts(); disc != 1 || jwks != 1 {
		t.Fatalf("after cached fetch: discovery=%d jwks=%d, want 1/1 (cache miss)", disc, jwks)
	}
	if metrics.hits != 1 || metrics.misses != 1 {
		t.Fatalf("metrics after cached fetch: hits=%d misses=%d, want 1/1", metrics.hits, metrics.misses)
	}
}

func TestHTTPJWKSSource_TrailingSlashNormalized(t *testing.T) {
	key := rsaTestKey(t)
	body := rsaJWKS(t, key, testKID)
	ts := newJWKSTestServer(t, body)

	src := NewHTTPJWKSSource(time.Minute, nil)
	ctx := context.Background()

	if _, err := src.GetJWKS(ctx, ts.srv.URL); err != nil {
		t.Fatalf("GetJWKS without slash: %v", err)
	}
	// Same issuer with a trailing slash should hit the cache, not refetch.
	if _, err := src.GetJWKS(ctx, ts.srv.URL+"/"); err != nil {
		t.Fatalf("GetJWKS with slash: %v", err)
	}
	if disc, jwks := ts.counts(); disc != 1 || jwks != 1 {
		t.Fatalf("trailing slash not normalized: discovery=%d jwks=%d, want 1/1", disc, jwks)
	}
}

func TestHTTPJWKSSource_Refresh(t *testing.T) {
	key := rsaTestKey(t)
	body := rsaJWKS(t, key, testKID)
	ts := newJWKSTestServer(t, body)

	// Negative TTL -> defaults to 5m; instead use a tiny positive TTL so the
	// entry expires and forces a refresh.
	src := NewHTTPJWKSSource(10*time.Millisecond, nil)
	ctx := context.Background()

	if _, err := src.GetJWKS(ctx, ts.srv.URL); err != nil {
		t.Fatalf("first GetJWKS: %v", err)
	}
	// Wait for the cache entry to expire.
	time.Sleep(20 * time.Millisecond)
	if _, err := src.GetJWKS(ctx, ts.srv.URL); err != nil {
		t.Fatalf("refresh GetJWKS: %v", err)
	}
	if disc, jwks := ts.counts(); disc != 2 || jwks != 2 {
		t.Fatalf("expected refetch after TTL: discovery=%d jwks=%d, want 2/2", disc, jwks)
	}
}

func TestHTTPJWKSSource_DiscoveryError(t *testing.T) {
	ts := newJWKSTestServer(t, []byte(`{"keys":[]}`))
	ts.failDiscovery = true
	src := NewHTTPJWKSSource(time.Minute, nil)
	_, err := src.GetJWKS(context.Background(), ts.srv.URL)
	if err == nil {
		t.Fatal("expected error when discovery returns non-200")
	}
}

func TestHTTPJWKSSource_MissingJWKSURI(t *testing.T) {
	ts := newJWKSTestServer(t, []byte(`{"keys":[]}`))
	ts.omitJWKSURI = true
	src := NewHTTPJWKSSource(time.Minute, nil)
	_, err := src.GetJWKS(context.Background(), ts.srv.URL)
	if err == nil || !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatalf("expected missing jwks_uri error, got %v", err)
	}
}

func TestHTTPJWKSSource_DiscoveryParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	src := NewHTTPJWKSSource(time.Minute, nil)
	_, err := src.GetJWKS(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("expected discovery parse error, got %v", err)
	}
}

func TestHTTPJWKSSource_JWKSFetchError(t *testing.T) {
	ts := newJWKSTestServer(t, []byte(`{"keys":[]}`))
	ts.failJWKS = true
	src := NewHTTPJWKSSource(time.Minute, nil)
	_, err := src.GetJWKS(context.Background(), ts.srv.URL)
	if err == nil {
		t.Fatal("expected error when jwks endpoint returns non-200")
	}
}

func TestHTTPJWKSSource_Defaults(t *testing.T) {
	// Zero TTL should not panic and should default internally; nil metrics
	// should be replaced by NopMetrics.
	src := NewHTTPJWKSSource(0, nil)
	if src.ttl != 5*time.Minute {
		t.Fatalf("expected default 5m TTL, got %v", src.ttl)
	}
	if src.metrics == nil {
		t.Fatal("expected non-nil metrics default")
	}
}

func TestNopMetrics_NoPanic(t *testing.T) {
	var m NopMetrics
	m.JWKSCacheHit("x")
	m.JWKSCacheMiss("x")
}
