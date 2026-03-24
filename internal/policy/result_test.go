package policy

import "testing"

func TestDecisionFields(t *testing.T) {
	dec := &Decision{
		Allow:      true,
		StatusCode: 200,
		Headers: map[string]string{
			"X-Policy": "ok",
		},
		Reason: "allowed",
	}

	if !dec.Allow || dec.StatusCode != 200 {
		t.Fatalf("unexpected decision core fields: %#v", dec)
	}
	if got := dec.Headers["X-Policy"]; got != "ok" {
		t.Fatalf("expected header X-Policy=ok, got %q", got)
	}
	if dec.Reason == "" {
		t.Fatalf("expected non-empty reason")
	}
}

func TestDecisionObligations(t *testing.T) {
	dec := &Decision{
		Allow:       true,
		StatusCode:  200,
		Obligations: map[string]any{"set_header_X_User": "alice"},
	}
	if dec.Obligations == nil || dec.Obligations["set_header_X_User"] != "alice" {
		t.Fatalf("expected obligations set_header_X_User=alice, got %#v", dec.Obligations)
	}
}
