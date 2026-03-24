package observability

import "testing"

var _ Metrics = NopMetrics{}

func TestNopMetricsNoPanic(t *testing.T) {
	var m NopMetrics
	m.AuthDecision(true, 200)
	m.JWKSCacheHit("iss")
	m.JWKSCacheMiss("iss")
	m.SessionStoreOp("get", true)
	m.PluginHealthState("p", "ok")
	m.LoginStarted()
	m.LoginCompleted(true)
	m.RefreshCompleted(false)
	m.LogoutCompleted()
}
