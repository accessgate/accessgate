package observability

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetrics implements Metrics using Prometheus counters and gauges.
type PrometheusMetrics struct {
	authDecisions   *prometheus.CounterVec
	jwksCache       *prometheus.CounterVec
	sessionStoreOps *prometheus.CounterVec
	pluginHealth    *prometheus.GaugeVec
	agentFlowOps    *prometheus.CounterVec
}

// NewPrometheusMetrics registers and returns Prometheus metrics for AccessGate.
// The returned handler serves /metrics; expose it on your metrics port or path.
//
// JWKS cache counters use the raw issuer string as a Prometheus label. Unbounded distinct
// issuers increase cardinality; prefer a small, known set of issuers or aggregate upstream.
func NewPrometheusMetrics(reg *prometheus.Registry) (*PrometheusMetrics, http.Handler) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	authDecisions := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "accessgate_auth_decisions_total", Help: "Total auth decisions by result and status code."},
		[]string{"result", "status_code"},
	)
	jwksCache := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "accessgate_jwks_cache_operations_total", Help: "JWKS cache hits and misses by issuer."},
		[]string{"issuer", "result"},
	)
	sessionStoreOps := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "accessgate_session_store_operations_total", Help: "Session store get/set operations by operation and result."},
		[]string{"operation", "result"},
	)
	pluginHealth := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "accessgate_plugin_health_state", Help: "Plugin health state (1=healthy, 0.5=degraded, 0=unhealthy/stopped)."},
		[]string{"plugin_id"},
	)
	agentFlowOps := prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "accessgate_agent_flow_operations_total", Help: "Agent login/refresh/logout flow outcomes by operation and result."},
		[]string{"operation", "result"},
	)
	reg.MustRegister(authDecisions, jwksCache, sessionStoreOps, pluginHealth, agentFlowOps)
	m := &PrometheusMetrics{
		authDecisions:   authDecisions,
		jwksCache:       jwksCache,
		sessionStoreOps: sessionStoreOps,
		pluginHealth:    pluginHealth,
		agentFlowOps:    agentFlowOps,
	}
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return m, handler
}

// AuthDecision implements Metrics.
func (p *PrometheusMetrics) AuthDecision(allow bool, statusCode int) {
	result := "deny"
	if allow {
		result = "allow"
	}
	p.authDecisions.WithLabelValues(result, strconv.Itoa(statusCode)).Inc()
}

// JWKSCacheHit implements Metrics.
func (p *PrometheusMetrics) JWKSCacheHit(issuer string) {
	p.jwksCache.WithLabelValues(issuer, "hit").Inc()
}

// JWKSCacheMiss implements Metrics.
func (p *PrometheusMetrics) JWKSCacheMiss(issuer string) {
	p.jwksCache.WithLabelValues(issuer, "miss").Inc()
}

// SessionStoreOp implements Metrics.
func (p *PrometheusMetrics) SessionStoreOp(operation string, success bool) {
	result := "error"
	if success {
		result = "ok"
	}
	p.sessionStoreOps.WithLabelValues(operation, result).Inc()
}

func pluginHealthGaugeValue(state string) float64 {
	switch state {
	case "healthy":
		return 1
	case "degraded":
		return 0.5
	case "stopped", "":
		return 0
	default:
		return 0
	}
}

// PluginHealthState implements Metrics.
func (p *PrometheusMetrics) PluginHealthState(pluginID string, state string) {
	p.pluginHealth.WithLabelValues(pluginID).Set(pluginHealthGaugeValue(state))
}

// LoginStarted implements Metrics.
func (p *PrometheusMetrics) LoginStarted() {
	p.agentFlowOps.WithLabelValues("login_start", "ok").Inc()
}

// LoginCompleted implements Metrics.
func (p *PrometheusMetrics) LoginCompleted(success bool) {
	result := "fail"
	if success {
		result = "ok"
	}
	p.agentFlowOps.WithLabelValues("login_end", result).Inc()
}

// RefreshCompleted implements Metrics.
func (p *PrometheusMetrics) RefreshCompleted(success bool) {
	result := "fail"
	if success {
		result = "ok"
	}
	p.agentFlowOps.WithLabelValues("refresh", result).Inc()
}

// LogoutCompleted implements Metrics.
func (p *PrometheusMetrics) LogoutCompleted() {
	p.agentFlowOps.WithLabelValues("logout", "ok").Inc()
}
