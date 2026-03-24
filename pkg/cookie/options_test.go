package cookie

import (
	"net/http"
	"testing"
)

func TestCookieOptionsConstruction(t *testing.T) {
	o := CookieOptions{
		Path: "/x", Domain: "d.example", Secure: true, HTTPOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: 60,
	}
	if o.Path != "/x" || o.MaxAge != 60 || o.SameSite != http.SameSiteStrictMode {
		t.Fatal(o)
	}
}
