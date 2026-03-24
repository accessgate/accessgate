package authz

import "testing"

func TestRequestFields(t *testing.T) {
	r := &Request{
		Protocol: "https", Method: "POST", Path: "/x",
		Headers: map[string]string{"H": "v"},
		Cookies: map[string]string{"c": "d"},
		Body:    []byte("{}"),
	}
	if r.Protocol != "https" || string(r.Body) != "{}" {
		t.Fatal(r)
	}
}
