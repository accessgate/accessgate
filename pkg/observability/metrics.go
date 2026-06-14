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

// ConnectorMetrics is an optional, additive extension implemented by PrometheusMetrics for the
// multi-connector / multi-route counters. It is kept separate from the frozen Metrics interface
// (v1 stability contract) so callers type-assert for it rather than requiring every Metrics
// implementation to provide these methods.
type ConnectorMetrics interface {
	// ConnectorCallback records an OIDC callback (login completion) outcome per connector.
	ConnectorCallback(connectorID string, success bool)
	// HandoffIssued records a handoff ticket issuance outcome per connector.
	HandoffIssued(connectorID string, success bool)
	// HandoffRedeemed records a handoff ticket redemption outcome per connector.
	HandoffRedeemed(connectorID string, success bool)
	// ProxyRouteOutcome records the outcome of a proxy request per route. outcome is one of
	// "allow", "auth_failure", "upstream_failure", or "route_miss".
	ProxyRouteOutcome(route, outcome string)
}

// NopMetrics discards all metrics. It is intended public surface: a no-op Metrics
// implementation that external integrators (and tests) can use as a default sink.
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

// NopMetrics also satisfies ConnectorMetrics so it can be used as a no-op sink for the
// multi-connector / multi-route counters.

// ConnectorCallback implements ConnectorMetrics.
func (NopMetrics) ConnectorCallback(connectorID string, success bool) {}

// HandoffIssued implements ConnectorMetrics.
func (NopMetrics) HandoffIssued(connectorID string, success bool) {}

// HandoffRedeemed implements ConnectorMetrics.
func (NopMetrics) HandoffRedeemed(connectorID string, success bool) {}

// ProxyRouteOutcome implements ConnectorMetrics.
func (NopMetrics) ProxyRouteOutcome(route, outcome string) {}
