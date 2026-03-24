package auth

import (
	"encoding/json"
	"testing"
)

func TestLoginStartRequestJSON(t *testing.T) {
	b, err := json.Marshal(LoginStartRequest{RedirectTo: "/app"})
	if err != nil {
		t.Fatal(err)
	}
	var got LoginStartRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.RedirectTo != "/app" {
		t.Fatalf("RedirectTo=%q", got.RedirectTo)
	}
}

func TestLoginEndRequestFields(t *testing.T) {
	req := LoginEndRequest{
		Code: "c", State: "s", Error: "e", ErrorDescription: "d", Host: "h.example",
	}
	if req.Code != "c" || req.State != "s" || req.Error != "e" || req.ErrorDescription != "d" || req.Host != "h.example" {
		t.Fatalf("unexpected struct: %+v", req)
	}
}

func TestLoginEndResponseFields(t *testing.T) {
	resp := LoginEndResponse{
		RedirectURL: "/ok", SetCookieValue: "v", ClearCookie: true,
	}
	if resp.RedirectURL != "/ok" || resp.SetCookieValue != "v" || !resp.ClearCookie {
		t.Fatalf("unexpected struct: %+v", resp)
	}
}
