package observability

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
)

// StdLogger implements Logger using log.Logger and emits key=value pairs.
type StdLogger struct {
	log *log.Logger
	pre []any // prefix keyvals
}

// NewStdLogger returns a Logger that writes to the given log.Logger.
// Keyvals must be alternating key, value. Prefer string keys; non-string keys are formatted
// with fmt.Sprint so they remain distinct. A trailing key without a value is ignored.
func NewStdLogger(l *log.Logger) *StdLogger {
	if l == nil {
		l = log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	}
	return &StdLogger{log: l, pre: nil}
}

func (s *StdLogger) appendKeyvals(buf *bytes.Buffer, keyvals []any) {
	for i := 0; i+1 < len(keyvals); i += 2 {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(formatKey(keyvals[i]))
		buf.WriteByte('=')
		buf.WriteString(formatValue(keyvals[i+1]))
	}
}

func formatKey(k any) string {
	switch v := k.(type) {
	case string:
		return v
	default:
		return fmt.Sprint(k)
	}
}

func formatValue(v any) string {
	switch x := v.(type) {
	case string:
		return quoteIfNeeded(x)
	default:
		return quoteIfNeeded(fmt.Sprint(v))
	}
}

// quoteIfNeeded wraps s in double quotes when it contains whitespace, a double-quote,
// or a backslash. Backslashes are escaped first so that the output remains valid logfmt
// (e.g. a Windows path C:\foo becomes "C:\\foo").
func quoteIfNeeded(s string) string {
	if !strings.ContainsAny(s, " \t\n\"\\") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// emit writes a log line at the given level. calldepth is 3 so that log.Logger
// reports the caller of Info/Warn/Error, not emit itself.
// appendKeyvals prepends a space when the buffer is non-empty, so no explicit
// separator is needed between the fixed header and the keyval sections.
func (s *StdLogger) emit(level, msg string, keyvals []any) {
	var buf bytes.Buffer
	buf.WriteString("level=")
	buf.WriteString(level)
	buf.WriteByte(' ')
	buf.WriteString("msg=")
	buf.WriteString(formatValue(msg))
	if len(s.pre) > 0 {
		s.appendKeyvals(&buf, s.pre)
	}
	if len(keyvals) > 0 {
		s.appendKeyvals(&buf, keyvals)
	}
	if err := s.log.Output(3, buf.String()); err != nil {
		_ = err
	}
}

// Info implements Logger.
func (s *StdLogger) Info(msg string, keyvals ...any) { s.emit("info", msg, keyvals) }

// Warn implements Logger.
func (s *StdLogger) Warn(msg string, keyvals ...any) { s.emit("warn", msg, keyvals) }

// Error implements Logger.
func (s *StdLogger) Error(msg string, keyvals ...any) { s.emit("error", msg, keyvals) }

// With implements Logger.
func (s *StdLogger) With(keyvals ...any) Logger {
	pre := make([]any, 0, len(s.pre)+len(keyvals))
	pre = append(pre, s.pre...)
	pre = append(pre, keyvals...)
	return &StdLogger{log: s.log, pre: pre}
}
