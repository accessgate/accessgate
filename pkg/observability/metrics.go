package observability

// Metrics records operational metrics for Prometheus or similar backends.
// All methods are safe for concurrent use.
type Metrics interface {
	// AuthDecision records a single auth decision (allow or deny).
	AuthDecision(allow bool, statusCode int)
	// JWKSCacheHit records a JWKS cache hit for the given issuer.
	JWKSCacheHit(issuer string)
	// JWKSCacheMiss records a JWKS cache miss for the given issuer.
	JWKSCacheMiss(issuer string)
	// SessionStoreOp records a session store get/set with success or failure.
	SessionStoreOp(operation string, success bool)
	// PluginHealthState sets the current health state (e.g. "healthy", "degraded") for a plugin.
	PluginHealthState(pluginID string, state string)

	// Agent flow counters — incremented by internal/auth/service.

	// LoginStarted records a login flow initiation.
	LoginStarted()
	// LoginCompleted records the outcome of a callback/token-exchange flow.
	LoginCompleted(success bool)
	// RefreshCompleted records the outcome of a token refresh attempt.
	RefreshCompleted(success bool)
	// LogoutCompleted records a completed logout flow.
	LogoutCompleted()
}

// NopMetrics discards all metrics.
type NopMetrics struct{}

// AuthDecision implements Metrics.
func (NopMetrics) AuthDecision(allow bool, statusCode int) {}

// JWKSCacheHit implements Metrics.
func (NopMetrics) JWKSCacheHit(issuer string) {}

// JWKSCacheMiss implements Metrics.
func (NopMetrics) JWKSCacheMiss(issuer string) {}

// SessionStoreOp implements Metrics.
func (NopMetrics) SessionStoreOp(operation string, success bool) {}

// PluginHealthState implements Metrics.
func (NopMetrics) PluginHealthState(pluginID string, state string) {}

// LoginStarted implements Metrics.
func (NopMetrics) LoginStarted() {}

// LoginCompleted implements Metrics.
func (NopMetrics) LoginCompleted(success bool) {}

// RefreshCompleted implements Metrics.
func (NopMetrics) RefreshCompleted(success bool) {}

// LogoutCompleted implements Metrics.
func (NopMetrics) LogoutCompleted() {}
