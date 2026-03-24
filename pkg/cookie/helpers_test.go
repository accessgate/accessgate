package cookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadSessionID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := ReadSessionID(r, "sid"); got != "" {
		t.Fatal(got)
	}
	r.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	if got := ReadSessionID(r, "sid"); got != "abc" {
		t.Fatal(got)
	}
}
