package auth

import (
	"encoding/json"
	"testing"
)

func TestSessionRequestFields(t *testing.T) {
	req := SessionRequest{SessionCookie: "c"}
	if req.SessionCookie != "c" {
		t.Fatal(req)
	}
}

func TestSessionResponseJSON(t *testing.T) {
	resp := SessionResponse{
		IsAuthenticated: true,
		User: &SessionUser{
			Sub: "u1", Email: "a@b.c", Roles: []string{"r"},
		},
		SetCookie: "x",
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got SessionResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.IsAuthenticated || got.User == nil || got.User.Sub != "u1" {
		t.Fatalf("got %+v", got)
	}
	if got.SetCookie != "x" {
		t.Fatalf("SetCookie=%q", got.SetCookie)
	}
}
