package observability

// Provider holds logger, metrics, and tracer for a binary. Use NewProvider to build.
type Provider struct {
	Logger  Logger
	Metrics Metrics
	Tracer  Tracer
}

// NewProvider returns a provider with the given components. Pass nil for any to use nop.
func NewProvider(logger Logger, metrics Metrics, tracer Tracer) *Provider {
	if logger == nil {
		logger = NopLogger{}
	}
	if metrics == nil {
		metrics = NopMetrics{}
	}
	if tracer == nil {
		tracer = NopTracer{}
	}
	return &Provider{
		Logger:  logger,
		Metrics: metrics,
		Tracer:  tracer,
	}
}
