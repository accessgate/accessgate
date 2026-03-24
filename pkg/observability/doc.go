// Package observability provides shared structured logging, metrics, and tracing
// for AccessGate binaries. Use Logger for structured logs, Metrics for
// Prometheus-compatible counters/gauges, and Tracer for optional distributed tracing.
// Use NewProvider to bundle all three, passing nil for any component to get a safe nop.
package observability
