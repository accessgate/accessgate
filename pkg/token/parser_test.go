package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestParseJWT_Valid(t *testing.T) {
	raw := strings.Join([]string{
		b64(`{"alg":"RS256","kid":"k1"}`),
		b64(`{"sub":"user-1"}`),
		b64("signature-bytes"),
	}, ".")

	header, payload, sig, err := ParseJWT(raw)
	if err != nil {
		t.Fatalf("ParseJWT returned error: %v", err)
	}
	if string(header) != `{"alg":"RS256","kid":"k1"}` {
		t.Fatalf("header = %s", header)
	}
	if string(payload) != `{"sub":"user-1"}` {
		t.Fatalf("payload = %s", payload)
	}
	if string(sig) != "signature-bytes" {
		t.Fatalf("signature = %s", sig)
	}
}

func TestParseJWT_WrongSegmentCount(t *testing.T) {
	tests := []string{
		"",
		"onlyonepart",
		b64("a") + "." + b64("b"), // two parts
		strings.Join([]string{b64("a"), b64("b"), b64("c"), "d"}, "."), // four parts
	}
	for _, raw := range tests {
		header, payload, sig, err := ParseJWT(raw)
		// Per contract, wrong segment count returns all-nil and no error.
		if err != nil {
			t.Fatalf("raw %q: expected nil error, got %v", raw, err)
		}
		if header != nil || payload != nil || sig != nil {
			t.Fatalf("raw %q: expected all-nil, got header=%v payload=%v sig=%v", raw, header, payload, sig)
		}
	}
}

func TestParseJWT_InvalidBase64(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"bad header", strings.Join([]string{"!!!", b64("b"), b64("c")}, ".")},
		{"bad payload", strings.Join([]string{b64("a"), "!!!", b64("c")}, ".")},
		{"bad signature", strings.Join([]string{b64("a"), b64("b"), "!!!"}, ".")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseJWT(tc.raw)
			if err == nil {
				t.Fatal("expected error for invalid base64 segment")
			}
		})
	}
}
