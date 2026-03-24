package observability

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// maxAttributeLen is the maximum string length for a span attribute value to prevent
// accidental secret leakage via long values.
const maxAttributeLen = 256

// NewOTLPTracerFromEnv returns a best-effort OTLP-backed tracer when OTEL env vars are set.
// If OTEL_EXPORTER_OTLP_ENDPOINT is missing or initialization fails, it returns NopTracer
// without writing to any logger — callers that need to detect this case should use
// NewOTLPTracerFromEnvWithShutdown and check whether the returned shutdown func is nil.
//
// Env-only design: no schema/config changes required.
func NewOTLPTracerFromEnv() Tracer {
	tr, _ := NewOTLPTracerFromEnvWithShutdown()
	return tr
}

// NewOTLPTracerFromEnvWithShutdown is like NewOTLPTracerFromEnv but also returns a shutdown
// function that flushes and releases the OTLP exporter before process exit.
// When tracing is disabled (no endpoint configured or init failure), shutdown is nil.
//
// Invoke shutdown with a context deadline before process exit so batched spans are exported:
//
//	tracer, shutdown := observability.NewOTLPTracerFromEnvWithShutdown()
//	defer func() {
//	    if shutdown != nil {
//	        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	        defer cancel()
//	        _ = shutdown(ctx)
//	    }
//	}()
func NewOTLPTracerFromEnvWithShutdown() (Tracer, func(context.Context) error) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return NopTracer{}, nil
	}

	protocol := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"))
	if protocol == "" {
		// OTel default is "grpc" for traces.
		protocol = "grpc"
	}

	serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = "accessgate"
	}

	// Parse endpoint into host/port and TLS mode.
	var (
		hostport string
		scheme   string
	)
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		hostport = u.Host
		scheme = u.Scheme
	} else {
		// No scheme present (e.g. "collector:4317") — use as-is.
		hostport = endpoint
	}

	// Best-effort initialization: never interrupt the main auth flows.
	ctx := context.Background()
	var (
		exporter sdktrace.SpanExporter
		err      error
	)

	switch strings.ToLower(protocol) {
	case "http/protobuf", "http":
		httpOpts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(hostport)}
		if scheme == "http" {
			httpOpts = append(httpOpts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, httpOpts...)
	case "grpc":
		grpcOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(hostport)}
		if scheme == "http" {
			grpcOpts = append(grpcOpts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, grpcOpts...)
	default:
		// Fall back to grpc for unknown protocol values.
		grpcOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(hostport)}
		if scheme == "http" {
			grpcOpts = append(grpcOpts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, grpcOpts...)
	}
	if err != nil || exporter == nil {
		// Best-effort: init failures silently degrade to NopTracer so the
		// main auth flows are never interrupted. Callers that need visibility
		// into init failures should use NewOTLPTracerFromEnvWithShutdown and
		// check for a nil shutdown func (which signals tracing is disabled).
		return NopTracer{}, nil
	}

	res := resource.NewWithAttributes(
		// Schema-less resource attributes are fine for env-only usage.
		"",
		attribute.String("service.name", serviceName),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)

	shutdown := func(shutdownCtx context.Context) error {
		return tp.Shutdown(shutdownCtx)
	}

	return &otelTracer{tracer: otel.Tracer(serviceName)}, shutdown
}

// otelTracer adapts OpenTelemetry to the Tracer interface.
type otelTracer struct {
	tracer trace.Tracer
}

func (t *otelTracer) StartSpan(ctx context.Context, name string, keyvals ...any) (context.Context, Span) {
	attrs := keyvalsToAttributes(keyvals)
	ctx, sp := t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, otelSpan{span: sp}
}

type otelSpan struct {
	span trace.Span
}

func (s otelSpan) End() { s.span.End() }

func keyvalsToAttributes(keyvals []any) []attribute.KeyValue {
	if len(keyvals) < 2 {
		return nil
	}
	out := make([]attribute.KeyValue, 0, len(keyvals)/2)
	for i := 0; i+1 < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		// Skip attributes whose key suggests sensitive data.
		if isSensitiveKey(k) {
			continue
		}
		out = append(out, attributeFromAny(k, keyvals[i+1]))
	}
	return out
}

// isSensitiveKey returns true if the attribute key suggests the value may be sensitive.
// The keyword list is deliberately specific to avoid dropping benign keys like "cache_key".
func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, kw := range []string{
		"password", "passwd", "secret", "token", "bearer", "credential",
		"authorization", "apikey", "api_key", "api-key",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func attributeFromAny(key string, v any) attribute.KeyValue {
	switch x := v.(type) {
	case string:
		if len(x) > maxAttributeLen {
			x = x[:maxAttributeLen] + "…"
		}
		return attribute.String(key, x)
	case []byte:
		s := string(x)
		if len(s) > maxAttributeLen {
			s = s[:maxAttributeLen] + "…"
		}
		return attribute.String(key, s)
	case bool:
		return attribute.Bool(key, x)
	case int:
		return attribute.Int64(key, int64(x))
	case int64:
		return attribute.Int64(key, x)
	case uint64:
		return attribute.Int64(key, int64(x))
	case float64:
		return attribute.Float64(key, x)
	default:
		s := fmt.Sprint(v)
		if len(s) > maxAttributeLen {
			s = s[:maxAttributeLen] + "…"
		}
		return attribute.String(key, s)
	}
}
