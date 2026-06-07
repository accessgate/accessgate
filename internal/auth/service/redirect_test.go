package service

import "testing"

func TestValidateRedirect_WildcardRejected(t *testing.T) {
	allowedOrigins := []string{"*"}
	allowedPaths := []string{"/"}
	result := ValidateRedirect("https://evil.example.com/steal", "https://app.example.com", allowedOrigins, allowedPaths)
	if result != "" {
		t.Errorf("wildcard origin should not match any target, got %q", result)
	}
}

func TestValidateRedirect_UnknownOriginRejected(t *testing.T) {
	allowedOrigins := []string{"https://app.example.com"}
	allowedPaths := []string{"/"}
	result := ValidateRedirect("https://attacker.com/pwn", "https://app.example.com", allowedOrigins, allowedPaths)
	if result != "" {
		t.Errorf("unknown origin should be rejected, got %q", result)
	}
}

func TestValidateRedirect_KnownOriginAllowed(t *testing.T) {
	allowedOrigins := []string{"https://app.example.com"}
	allowedPaths := []string{"/"}
	result := ValidateRedirect("https://app.example.com/dashboard", "https://app.example.com", allowedOrigins, allowedPaths)
	if result == "" {
		t.Error("known origin should be allowed")
	}
}

func TestValidateRedirect_BaseOriginAllowedWithoutExplicitOrigin(t *testing.T) {
	allowedPaths := []string{"/"}
	result := ValidateRedirect("https://app.example.com/link/complete?state=abc", "https://app.example.com", nil, allowedPaths)
	if result != "https://app.example.com/link/complete?state=abc" {
		t.Fatalf("expected same-origin absolute URL to be allowed, got %q", result)
	}
}

func TestValidateRedirect_PathAllowed(t *testing.T) {
	allowedPaths := []string{"/"}
	result := ValidateRedirect("/dashboard", "https://app.example.com", nil, allowedPaths)
	if result == "" {
		t.Error("relative path redirect should be allowed")
	}
}

func TestValidateRedirect_ProtocolRelativeRejected(t *testing.T) {
	// Browsers treat "//host" and "/\host" as absolute URLs to another host.
	// A leading-slash-only check would let these through as "local paths"
	// (CWE-601 open redirect); they must be rejected.
	cases := []string{
		"//evil.example.com/steal",
		"/\\evil.example.com/steal",
		"//evil.example.com",
	}
	for _, target := range cases {
		result := ValidateRedirect(target, "https://app.example.com", nil, []string{"/"})
		if result != "" {
			t.Errorf("protocol-relative redirect %q must be rejected, got %q", target, result)
		}
	}
}

func TestValidateRedirect_FileSchemeRejected(t *testing.T) {
	allowedOrigins := []string{"*"}
	result := ValidateRedirect("file:///etc/passwd", "https://app.example.com", allowedOrigins, nil)
	if result != "" {
		t.Errorf("file:// scheme must be rejected, got %q", result)
	}
}
