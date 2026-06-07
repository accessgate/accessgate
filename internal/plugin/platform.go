package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultMaxPluginIDLength = 128
	defaultMaxCacheKeyLength = 256
)

var (
	ErrInvalidPluginID = errors.New("plugin: invalid plugin id")
	ErrCacheKeyTooLong = errors.New("plugin: cache key too long")
)

// PlatformOptions configures bounds for the shared plugin platform.
type PlatformOptions struct {
	MaxPluginIDLength int
	MaxCacheKeyLength int
}

// SharedPlatform provides bounded, shared services and can scope them per plugin.
type SharedPlatform struct {
	logger  Logger
	metrics Metrics
	cache   Cache
	secrets Secrets
	clock   Clock

	maxPluginIDLength int
	maxCacheKeyLength int
}

// NewSharedPlatform builds a bounded shared plugin platform from host services.
func NewSharedPlatform(base HostServices, opts PlatformOptions) *SharedPlatform {
	maxPluginIDLength := opts.MaxPluginIDLength
	if maxPluginIDLength <= 0 {
		maxPluginIDLength = defaultMaxPluginIDLength
	}
	maxCacheKeyLength := opts.MaxCacheKeyLength
	if maxCacheKeyLength <= 0 {
		maxCacheKeyLength = defaultMaxCacheKeyLength
	}
	return &SharedPlatform{
		logger:            base.Logger(),
		metrics:           base.Metrics(),
		cache:             base.Cache(),
		secrets:           base.Secrets(),
		clock:             base.Clock(),
		maxPluginIDLength: maxPluginIDLength,
		maxCacheKeyLength: maxCacheKeyLength,
	}
}

// Scope returns plugin-scoped host services with bounded platform behavior.
func (p *SharedPlatform) Scope(id PluginID) (ScopedHost, error) {
	sid := strings.TrimSpace(string(id))
	if sid == "" || len(sid) > p.maxPluginIDLength {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPluginID, id)
	}
	return &scopedHost{platform: p, pluginID: sid}, nil
}

type scopedHost struct {
	platform *SharedPlatform
	pluginID string
}

func (h *scopedHost) PluginID() string { return h.pluginID }
func (h *scopedHost) Logger() Logger {
	return &scopedLogger{base: h.platform.logger, pluginID: h.pluginID}
}
func (h *scopedHost) Metrics() Metrics {
	return &scopedMetrics{base: h.platform.metrics, pluginID: h.pluginID}
}
func (h *scopedHost) Cache() Cache {
	return &scopedCache{base: h.platform.cache, pluginID: h.pluginID, maxKeyLength: h.platform.maxCacheKeyLength}
}
func (h *scopedHost) Secrets() Secrets { return h.platform.secrets }
func (h *scopedHost) Clock() Clock     { return h.platform.clock }

type scopedLogger struct {
	base     Logger
	pluginID string
}

func (l *scopedLogger) Debug(msg string, fields map[string]any) {
	l.base.Debug(msg, withPluginField(fields, l.pluginID))
}
func (l *scopedLogger) Info(msg string, fields map[string]any) {
	l.base.Info(msg, withPluginField(fields, l.pluginID))
}
func (l *scopedLogger) Warn(msg string, fields map[string]any) {
	l.base.Warn(msg, withPluginField(fields, l.pluginID))
}
func (l *scopedLogger) Error(msg string, fields map[string]any) {
	l.base.Error(msg, withPluginField(fields, l.pluginID))
}

func withPluginField(fields map[string]any, pluginID string) map[string]any {
	if fields == nil {
		return map[string]any{"plugin_id": pluginID}
	}
	cp := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		cp[k] = v
	}
	cp["plugin_id"] = pluginID
	return cp
}

type scopedMetrics struct {
	base     Metrics
	pluginID string
}

func (m *scopedMetrics) Counter(name string, labels map[string]string) Counter {
	return m.base.Counter(m.name(name), withPluginLabel(labels, m.pluginID))
}

func (m *scopedMetrics) Gauge(name string, labels map[string]string) Gauge {
	return m.base.Gauge(m.name(name), withPluginLabel(labels, m.pluginID))
}

func (m *scopedMetrics) Histogram(name string, labels map[string]string) Histogram {
	return m.base.Histogram(m.name(name), withPluginLabel(labels, m.pluginID))
}

func (m *scopedMetrics) name(name string) string {
	if strings.TrimSpace(name) == "" {
		return "plugin." + m.pluginID + ".invalid"
	}
	return "plugin." + m.pluginID + "." + name
}

func withPluginLabel(labels map[string]string, pluginID string) map[string]string {
	if labels == nil {
		return map[string]string{"plugin_id": pluginID}
	}
	cp := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		cp[k] = v
	}
	cp["plugin_id"] = pluginID
	return cp
}

type scopedCache struct {
	base         Cache
	pluginID     string
	maxKeyLength int
}

func (c *scopedCache) Get(ctx context.Context, key string) (string, error) {
	ck, err := c.key(key)
	if err != nil {
		return "", err
	}
	return c.base.Get(ctx, ck)
}

func (c *scopedCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	ck, err := c.key(key)
	if err != nil {
		return err
	}
	return c.base.Set(ctx, ck, value, ttl)
}

func (c *scopedCache) Del(ctx context.Context, key string) error {
	ck, err := c.key(key)
	if err != nil {
		return err
	}
	return c.base.Del(ctx, ck)
}

func (c *scopedCache) key(key string) (string, error) {
	if len(key) > c.maxKeyLength {
		return "", fmt.Errorf("%w: %d > %d", ErrCacheKeyTooLong, len(key), c.maxKeyLength)
	}
	return "plugin:" + c.pluginID + ":" + key, nil
}
