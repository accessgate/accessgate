// Package contract: SDK/agent response shape contract (Go agent types produce JSON expected by JS/BFF).
package contract

import (
	"encoding/json"
	"testing"

	"github.com/accessgate/accessgate/pkg/auth"
)

// TestAgentSessionResponse_JSONShape ensures SessionResponse JSON has the keys
// expected by the JS SDK (is_authenticated, user with sub, etc.).
func TestAgentSessionResponse_JSONShape(t *testing.T) {
	resp := auth.SessionResponse{
		IsAuthenticated: true,
		User: &auth.SessionUser{
			Sub:               "user-1",
			Email:             "u@example.com",
			PreferredUsername: "u",
			Name:              "User",
			Roles:             []string{"user"},
			Groups:            []string{"g1"},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["is_authenticated"]; !ok {
		t.Error("expected is_authenticated key (snake_case for JS/BFF)")
	}
	user, ok := m["user"].(map[string]any)
	if !ok || user == nil {
		t.Fatal("expected user object")
	}
	if user["sub"] != "user-1" {
		t.Errorf("user.sub = %v", user["sub"])
	}
}
