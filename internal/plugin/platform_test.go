package plugin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type captureLogger struct {
	fields map[string]any
}

func (l *captureLogger) Debug(_ string, fields map[string]any) { l.fields = fields }
func (l *captureLogger) Info(_ string, fields map[string]any)  { l.fields = fields }
func (l *captureLogger) Warn(_ string, fields map[string]any)  { l.fields = fields }
func (l *captureLogger) Error(_ string, fields map[string]any) { l.fields = fields }

type captureMetrics struct {
	name   string
	labels map[string]string
}

func (m *captureMetrics) Counter(name string, labels map[string]string) Counter {
	m.name, m.labels = name, labels
	return noopCounter{}
}
func (m *captureMetrics) Gauge(name string, labels map[string]string) Gauge {
	m.name, m.labels = name, labels
	return noopGauge{}
}
func (m *captureMetrics) Histogram(name string, labels map[string]string) Histogram {
	m.name, m.labels = name, labels
	return noopHistogram{}
}

type noopCounter struct{}

func (noopCounter) Add(_ float64) {}

type noopGauge struct{}

func (noopGauge) Set(_ float64) {}

type noopHistogram struct{}

func (noopHistogram) Observe(_ float64) {}

type captureCache struct {
	lastKey string
}

func (c *captureCache) Get(_ context.Context, key string) (string, error) { c.lastKey = key; return "", nil }
func (c *captureCache) Set(_ context.Context, key string, _ string, _ time.Duration) error {
	c.lastKey = key
	return nil
}
func (c *captureCache) Del(_ context.Context, key string) error { c.lastKey = key; return nil }

type baseHost struct {
	logger  Logger
	metrics Metrics
	cache   Cache
}

func (h *baseHost) Logger() Logger   { return h.logger }
func (h *baseHost) Metrics() Metrics { return h.metrics }
func (h *baseHost) Cache() Cache     { return h.cache }
func (h *baseHost) Secrets() Secrets { return nil }
func (h *baseHost) Clock() Clock     { return stubClock{} }

func TestSharedPlatformScopeInvalidID(t *testing.T) {
	p := NewSharedPlatform(&baseHost{}, PlatformOptions{MaxPluginIDLength: 4})
	_, err := p.Scope(PluginID("too-long"))
	if err == nil || !errors.Is(err, ErrInvalidPluginID) {
		t.Fatalf("expected ErrInvalidPluginID, got %v", err)
	}
}

func TestSharedPlatformScopeAddsPluginContext(t *testing.T) {
	lg := &captureLogger{}
	m := &captureMetrics{}
	c := &captureCache{}
	p := NewSharedPlatform(&baseHost{logger: lg, metrics: m, cache: c}, PlatformOptions{})

	h, err := p.Scope("provider:oidc")
	if err != nil {
		t.Fatal(err)
	}

	h.Logger().Info("hello", map[string]any{"k": "v"})
	if lg.fields["plugin_id"] != "provider:oidc" {
		t.Fatalf("plugin_id missing from log fields: %v", lg.fields)
	}

	h.Metrics().Counter("requests_total", nil)
	if m.name != "plugin.provider:oidc.requests_total" {
		t.Fatalf("unexpected metric name %q", m.name)
	}
	if m.labels["plugin_id"] != "provider:oidc" {
		t.Fatalf("plugin_id missing from metric labels: %v", m.labels)
	}

	if err := h.Cache().Set(context.Background(), "abc", "1", time.Second); err != nil {
		t.Fatal(err)
	}
	if c.lastKey != "plugin:provider:oidc:abc" {
		t.Fatalf("unexpected cache key %q", c.lastKey)
	}
}

func TestSharedPlatformScopeBoundsCacheKeyLength(t *testing.T) {
	p := NewSharedPlatform(&baseHost{cache: &captureCache{}}, PlatformOptions{MaxCacheKeyLength: 3})
	h, err := p.Scope("p1")
	if err != nil {
		t.Fatal(err)
	}
	err = h.Cache().Set(context.Background(), strings.Repeat("a", 4), "x", time.Second)
	if err == nil || !errors.Is(err, ErrCacheKeyTooLong) {
		t.Fatalf("expected ErrCacheKeyTooLong, got %v", err)
	}
}
