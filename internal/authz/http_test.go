package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestProxyToUpstream_StripsSpoofedIdentityHeaders verifies the trust boundary:
// client-supplied identity headers must never reach the upstream, and the proxy's
// verified upstreamHeaders must be the only source of those headers.
func TestProxyToUpstream_StripsSpoofedIdentityHeaders(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	inbound := httptest.NewRequest(http.MethodGet, "http://edge.example/graphql", nil)
	// Client attempts to spoof identity. None of these should reach the upstream
	// unless the proxy itself re-injects a verified value.
	inbound.Header.Set("X-User-Id", "attacker")
	inbound.Header.Set("Authorization", "Bearer forged")
	inbound.Header.Set("X-Roles", "admin")
	inbound.Header.Set("X-Tenant-Id", "evil-tenant")
	inbound.Header.Set("X-Custom", "keep-me") // non-identity header must pass through

	// Verified, proxy-derived headers (what defaultHeaderBuilder would produce).
	verified := map[string]string{
		"X-User-Id":     "verified-user",
		"Authorization": "Bearer verified",
	}

	rec := httptest.NewRecorder()
	if err := ProxyToUpstream(context.Background(), rec, inbound, upstream.URL, verified, nil); err != nil {
		t.Fatalf("ProxyToUpstream: %v", err)
	}

	if v := got.Get("X-User-Id"); v != "verified-user" {
		t.Errorf("X-User-Id = %q, want verified-user (spoof must be replaced)", v)
	}
	if v := got.Get("Authorization"); v != "Bearer verified" {
		t.Errorf("Authorization = %q, want Bearer verified", v)
	}
	// X-Roles / X-Tenant-Id were spoofed but not re-injected -> must be absent.
	if v := got.Get("X-Roles"); v != "" {
		t.Errorf("X-Roles = %q, want empty (spoofed identity header must be stripped)", v)
	}
	if v := got.Get("X-Tenant-Id"); v != "" {
		t.Errorf("X-Tenant-Id = %q, want empty (spoofed identity header must be stripped)", v)
	}
	if v := got.Get("X-Custom"); v != "keep-me" {
		t.Errorf("X-Custom = %q, want keep-me (non-identity header must pass through)", v)
	}
}

func TestValidateUpstreamURL_RejectsFileScheme(t *testing.T) {
	u, _ := url.Parse("file:///etc/passwd")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("file:// scheme should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsGopherScheme(t *testing.T) {
	u, _ := url.Parse("gopher://127.0.0.1:70/")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("gopher:// scheme should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsLoopback(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/admin")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("loopback address should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsIPv6Loopback(t *testing.T) {
	u, _ := url.Parse("http://[::1]/admin")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("IPv6 loopback should be rejected")
	}
}

func TestValidateUpstreamURL_RejectsPrivateRFC1918(t *testing.T) {
	for _, addr := range []string{
		"http://10.0.0.1/",
		"http://172.16.0.1/",
		"http://192.168.1.1/",
	} {
		u, _ := url.Parse(addr)
		if err := validateUpstreamURL(u); err == nil {
			t.Errorf("private address %s should be rejected", addr)
		}
	}
}

func TestValidateUpstreamURL_RejectsLinkLocal(t *testing.T) {
	u, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	if err := validateUpstreamURL(u); err == nil {
		t.Error("link-local (metadata) address should be rejected")
	}
}
