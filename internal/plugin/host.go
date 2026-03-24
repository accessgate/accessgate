package plugin

import (
	"context"
	"time"
)

// Logger is the minimal logging interface exposed to plugins.
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, fields map[string]any)
}

// Counter is a monotonically increasing metric.
type Counter interface {
	Add(delta float64)
}

// Gauge is a point-in-time metric.
type Gauge interface {
	Set(value float64)
}

// Histogram records observations into buckets.
type Histogram interface {
	Observe(value float64)
}

// Metrics exposes basic metric constructors for plugins.
type Metrics interface {
	Counter(name string, labels map[string]string) Counter
	Gauge(name string, labels map[string]string) Gauge
	Histogram(name string, labels map[string]string) Histogram
}

// Cache is a simple key/value store surface for plugins.
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// Secrets exposes secret lookup by name.
type Secrets interface {
	Resolve(ctx context.Context, name string) (string, error)
}

// Clock provides time to plugins, mainly to improve testability.
type Clock interface {
	Now() time.Time
}

// HostServices is the aggregate set of services a plugin can use.
type HostServices interface {
	Logger() Logger
	Metrics() Metrics
	Cache() Cache
	Secrets() Secrets
	Clock() Clock
}

// ScopedHost wraps HostServices with plugin-specific scoping (e.g. metric prefixes, log fields).
type ScopedHost interface {
	HostServices

	// PluginID returns the identifier of the plugin this host is scoped to.
	PluginID() string
}
