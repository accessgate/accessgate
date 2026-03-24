package auth

import "testing"

func TestLogoutRequestFields(t *testing.T) {
	req := LogoutRequest{
		SessionCookie: "sess",
		RedirectTo:    "/after",
		Origin:        "https://app",
		Referer:       "https://app/logout",
	}
	if req.SessionCookie != "sess" || req.RedirectTo != "/after" {
		t.Fatalf("unexpected: %+v", req)
	}
}

func TestLogoutResponseFields(t *testing.T) {
	resp := LogoutResponse{RedirectURL: "https://idp/end", ClearCookie: true}
	if resp.RedirectURL == "" || !resp.ClearCookie {
		t.Fatalf("unexpected: %+v", resp)
	}
}
