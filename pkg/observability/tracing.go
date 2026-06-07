package observability

import "context"

// Span represents a tracing span. Call End when done.
type Span interface {
	End()
}

// Tracer provides optional distributed tracing. Default is no-op.
type Tracer interface {
	StartSpan(ctx context.Context, name string, keyvals ...any) (context.Context, Span)
}

// NopTracer does not record spans. It is intended public surface: a no-op Tracer
// implementation usable by external integrators and as the default when tracing is
// not configured (see NewOTLPTracerFromEnvWithShutdown). Its span type is unexported.
type NopTracer struct{}

type nopSpan struct{}

func (nopSpan) End() {}

// StartSpan implements Tracer.
func (NopTracer) StartSpan(ctx context.Context, name string, keyvals ...any) (context.Context, Span) {
	return ctx, nopSpan{}
}
