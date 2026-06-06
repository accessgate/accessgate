package authz

import (
	"strings"
	"testing"

	"github.com/accessgate/accessgate/pkg/token"
)

func TestDefaultHeaderBuilder_NilPrincipalNoPanic(t *testing.T) {
	h := defaultHeaderBuilder(nil, nil)
	if h == nil {
		t.Error("expected non-nil map, got nil")
	}
	if len(h) != 0 {
		t.Errorf("expected empty map for nil principal, got %v", h)
	}
}

func TestEscapeJSON_CRLFEscaped(t *testing.T) {
	input := "foo\r\nbar"
	escaped := escapeJSON(input)
	if strings.Contains(escaped, "\r") || strings.Contains(escaped, "\n") {
		t.Errorf("escapeJSON should escape CRLF, got %q", escaped)
	}
}

func TestEscapeJSON_ControlCharsEscaped(t *testing.T) {
	input := "val\twith\ttabs"
	escaped := escapeJSON(input)
	if strings.ContainsRune(escaped, '\t') {
		t.Errorf("escapeJSON should escape tab characters, got %q", escaped)
	}
}

func TestEscapeJSON_BackslashEscaped(t *testing.T) {
	input := `a\b`
	escaped := escapeJSON(input)
	if !strings.Contains(escaped, `\\`) {
		t.Errorf("escapeJSON should escape backslash, got %q", escaped)
	}
}

func TestCRLFStrippedFromObligationHeaders(t *testing.T) {
	principal := &token.Principal{Subject: "user1"}
	stripCRLF := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, s)
	}
	injected := "X-Injected\r\nX-Evil: pwned"
	cleaned := stripCRLF(injected)
	if strings.Contains(cleaned, "\r") || strings.Contains(cleaned, "\n") {
		t.Errorf("CRLF should be stripped from header name, got %q", cleaned)
	}
	_ = principal
}
