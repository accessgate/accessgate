package observability

// Logger provides structured logging. Implementations should support key-value fields.
type Logger interface {
	Info(msg string, keyvals ...any)
	Warn(msg string, keyvals ...any)
	Error(msg string, keyvals ...any)
	With(keyvals ...any) Logger
}

// NopLogger discards all log output.
type NopLogger struct{}

// Info implements Logger.
func (NopLogger) Info(msg string, keyvals ...any) {}

// Warn implements Logger.
func (NopLogger) Warn(msg string, keyvals ...any) {}

// Error implements Logger.
func (NopLogger) Error(msg string, keyvals ...any) {}

// With implements Logger.
func (n NopLogger) With(keyvals ...any) Logger { return n }
