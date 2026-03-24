package auth

import "testing"

func TestRefreshRequestFields(t *testing.T) {
	req := RefreshRequest{SessionCookie: "raw"}
	if req.SessionCookie != "raw" {
		t.Fatal(req)
	}
}

func TestRefreshResponseFields(t *testing.T) {
	resp := RefreshResponse{SetCookieValue: "new", Refreshed: true}
	if resp.SetCookieValue != "new" || !resp.Refreshed {
		t.Fatal(resp)
	}
}
