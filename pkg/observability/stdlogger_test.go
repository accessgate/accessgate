package observability

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestStdLoggerInfoContainsMessage(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "hello") || !strings.Contains(out, "k=v") {
		t.Fatalf("got %q", out)
	}
}

func TestStdLoggerWithPrefix(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0)).With("trace", "1")
	l.Warn("x")
	if !strings.Contains(buf.String(), "trace=1") {
		t.Fatal(buf.String())
	}
}

func TestStdLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	out := buf.String()
	if !strings.Contains(out, "level=info") || !strings.Contains(out, "level=warn") || !strings.Contains(out, "level=error") {
		t.Fatalf("missing level fields: %q", out)
	}
}

func TestStdLoggerQuotedValue(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("has space")
	if !strings.Contains(buf.String(), `msg="has space"`) {
		t.Fatalf("expected quoted msg, got: %q", buf.String())
	}
}

func TestStdLoggerBackslashEscaping(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("path", "k", `C:\Users\name`)
	// Backslash must be escaped before the surrounding quotes are added.
	if !strings.Contains(buf.String(), `k="C:\\Users\\name"`) {
		t.Fatalf("expected escaped backslash, got: %q", buf.String())
	}
}

func TestStdLoggerNonStringKey(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("m", 42, "x")
	// Non-string keys are formatted with fmt.Sprint, not dropped.
	if !strings.Contains(buf.String(), "42=x") {
		t.Fatalf("expected numeric key 42, got: %q", buf.String())
	}
}

func TestStdLoggerOddKeyvalsIgnored(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdLogger(log.New(&buf, "", 0))
	l.Info("m", "onlykey")
	if strings.Contains(buf.String(), "onlykey=") {
		t.Fatalf("trailing key without value should be omitted, got: %q", buf.String())
	}
}
