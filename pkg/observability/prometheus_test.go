package observability

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPrometheusMetricsMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, h := NewPrometheusMetrics(reg)
	m.AuthDecision(true, 200)
	m.JWKSCacheHit("i")
	m.JWKSCacheMiss("i")
	m.SessionStoreOp("get", true)
	m.PluginHealthState("pid", "healthy")
	m.LoginStarted()
	m.LoginCompleted(true)
	m.RefreshCompleted(false)
	m.LogoutCompleted()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "accessgate_") {
		t.Fatalf("metrics response: %d %s", rr.Code, body)
	}
}

func TestPrometheusMetrics_AgentFlowOpsMetricName(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, _ := NewPrometheusMetrics(reg)
	m.LoginStarted()
	m.LoginCompleted(true)
	m.RefreshCompleted(false)
	m.LogoutCompleted()

	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP accessgate_agent_flow_operations_total Agent login/refresh/logout flow outcomes by operation and result.
# TYPE accessgate_agent_flow_operations_total counter
accessgate_agent_flow_operations_total{operation="login_start",result="ok"} 1
accessgate_agent_flow_operations_total{operation="login_end",result="ok"} 1
accessgate_agent_flow_operations_total{operation="refresh",result="fail"} 1
accessgate_agent_flow_operations_total{operation="logout",result="ok"} 1
`), "accessgate_agent_flow_operations_total"); err != nil {
		t.Fatal(err)
	}
}

func TestPrometheusMetrics_MultiConnectorCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, _ := NewPrometheusMetrics(reg)
	m.ConnectorCallback("telegram", true)
	m.HandoffIssued("telegram", true)
	m.HandoffRedeemed("telegram", false)
	m.ProxyRouteOutcome("web", "allow")
	m.ProxyRouteOutcome("", "route_miss")

	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP accessgate_auth_callbacks_total OIDC callback (login completion) outcomes by connector and result.
# TYPE accessgate_auth_callbacks_total counter
accessgate_auth_callbacks_total{connector_id="telegram",result="ok"} 1
`), "accessgate_auth_callbacks_total"); err != nil {
		t.Fatal(err)
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP accessgate_auth_handoff_total Handoff ticket issue/redeem outcomes by operation, connector, and result.
# TYPE accessgate_auth_handoff_total counter
accessgate_auth_handoff_total{connector_id="telegram",operation="issue",result="ok"} 1
accessgate_auth_handoff_total{connector_id="telegram",operation="redeem",result="fail"} 1
`), "accessgate_auth_handoff_total"); err != nil {
		t.Fatal(err)
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP accessgate_proxy_route_outcomes_total Proxy request outcomes by route and outcome (allow/auth_failure/upstream_failure/route_miss).
# TYPE accessgate_proxy_route_outcomes_total counter
accessgate_proxy_route_outcomes_total{outcome="allow",route="web"} 1
accessgate_proxy_route_outcomes_total{outcome="route_miss",route=""} 1
`), "accessgate_proxy_route_outcomes_total"); err != nil {
		t.Fatal(err)
	}
}

func TestPrometheusMetrics_PluginHealthState(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, _ := NewPrometheusMetrics(reg)
	m.PluginHealthState("p1", "healthy")
	m.PluginHealthState("p2", "degraded")
	m.PluginHealthState("p3", "stopped")
	m.PluginHealthState("p4", "unknown")

	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP accessgate_plugin_health_state Plugin health state (1=healthy, 0.5=degraded, 0=unhealthy/stopped).
# TYPE accessgate_plugin_health_state gauge
accessgate_plugin_health_state{plugin_id="p1"} 1
accessgate_plugin_health_state{plugin_id="p2"} 0.5
accessgate_plugin_health_state{plugin_id="p3"} 0
accessgate_plugin_health_state{plugin_id="p4"} 0
`), "accessgate_plugin_health_state"); err != nil {
		t.Fatal(err)
	}
}
