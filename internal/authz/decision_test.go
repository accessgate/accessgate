package authz

import (
	"testing"

	"github.com/accessgate/accessgate/pkg/cookie"
)

func TestResponseFields(t *testing.T) {
	resp := &Response{
		Allow:           true,
		UpstreamHeaders: map[string]string{"X-A": "1"},
		SetCookies:      []cookie.OutCookie{{Name: "n", Value: "v"}},
		StatusCode:      200,
		Body:            []byte("{}"),
	}
	if !resp.Allow || resp.StatusCode != 200 {
		t.Fatal(resp)
	}
}
