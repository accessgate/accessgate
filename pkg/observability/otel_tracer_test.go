package observability

import (
	"testing"
)

func TestNewOTLPTracerFromEnv_NoEndpointUsesNop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	tr := NewOTLPTracerFromEnv()
	if _, ok := tr.(NopTracer); !ok {
		t.Fatalf("expected NopTracer without endpoint, got %T", tr)
	}
}

func TestNewOTLPTracerFromEnvWithShutdown_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	tr, shutdown := NewOTLPTracerFromEnvWithShutdown()
	if _, ok := tr.(NopTracer); !ok {
		t.Fatalf("expected NopTracer without endpoint, got %T", tr)
	}
	if shutdown != nil {
		t.Fatal("expected nil shutdown when tracing is disabled")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"password", "user_password", "token", "X-Api-Key", "authorization", "bearer_token", "client_secret"}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("expected %q to be sensitive", k)
		}
	}

	safe := []string{"operation", "cache_key", "request_id", "status_code", "issuer"}
	for _, k := range safe {
		if isSensitiveKey(k) {
			t.Errorf("expected %q to be safe, but was filtered", k)
		}
	}
}

func TestKeyvalsToAttributes_SensitiveDropped(t *testing.T) {
	attrs := keyvalsToAttributes([]any{"operation", "login", "password", "secret123", "user_id", "42"})
	for _, kv := range attrs {
		if string(kv.Key) == "password" {
			t.Fatal("password attribute should have been filtered")
		}
	}
	found := false
	for _, kv := range attrs {
		if string(kv.Key) == "operation" {
			found = true
		}
	}
	if !found {
		t.Fatal("operation attribute should be present")
	}
}
