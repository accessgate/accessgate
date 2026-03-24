package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyEvaluate_WithBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "policy.rego")

	regoSrc := `
package accessgate

decision := {"allow": true, "status_code": 200, "reason": "", "headers": {}, "obligations": {}} if {
  input.Path == "/public"
} else := {"allow": false, "status_code": 403, "reason": "denied by policy", "headers": {}, "obligations": {}} if {
  true
}
`
	if err := os.WriteFile(p, []byte(regoSrc), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}

	eng := NewRegoEngine(DefaultFallbackDeny)
	if err := eng.Load(p); err != nil {
		t.Fatalf("Load: %v", err)
	}

	dec1, err := eng.Evaluate(context.Background(), Input{Protocol: "http", Method: "GET", Path: "/public"})
	if err != nil {
		t.Fatalf("Evaluate /public: %v", err)
	}
	if !dec1.Allow || dec1.StatusCode != 200 {
		t.Fatalf("expected allow 200 for /public, got Allow=%v StatusCode=%d Reason=%q", dec1.Allow, dec1.StatusCode, dec1.Reason)
	}

	dec2, err := eng.Evaluate(context.Background(), Input{Protocol: "http", Method: "GET", Path: "/admin"})
	if err != nil {
		t.Fatalf("Evaluate /admin: %v", err)
	}
	if dec2.Allow || dec2.StatusCode != 403 {
		t.Fatalf("expected deny 403 for /admin, got Allow=%v StatusCode=%d Reason=%q", dec2.Allow, dec2.StatusCode, dec2.Reason)
	}
}
