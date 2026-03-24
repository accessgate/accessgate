package cookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionCookieConfigOptionsDefaultPath(t *testing.T) {
	c := SessionCookieConfig{Name: "n", Path: ""}
	opts := c.Options()
	if opts.Path != "/" {
		t.Fatal(opts.Path)
	}
}

func TestDefaultSessionCookieConfig(t *testing.T) {
	c := DefaultSessionCookieConfig("sess")
	if c.Name != "sess" || !c.Secure || !c.HTTPOnly {
		t.Fatalf("%+v", c)
	}
}

func TestWriteOutCookie(t *testing.T) {
	w := httptest.NewRecorder()
	WriteOutCookie(w, OutCookie{
		Name: "a", Value: "b",
		Options: CookieOptions{Path: "/p", Secure: true, HTTPOnly: true, SameSite: http.SameSiteLaxMode},
	})
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "a" || cookies[0].Value != "b" {
		t.Fatalf("%+v", cookies)
	}
}
