package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthClientResolveUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewAuthClient(srv.URL, "sid")
	got, err := c.Resolve(context.Background(), "raw")
	if err != nil || got != nil {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestAuthClientResolveOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Get("Cookie"); c != "sid=abc" {
			t.Fatalf("cookie %q", c)
		}
		_ = json.NewEncoder(w).Encode(ResolveResponse{
			AccessToken: "t",
			Claims:      map[string]any{"sub": "u1"},
		})
	}))
	defer srv.Close()
	c := NewAuthClient(srv.URL, "sid")
	got, err := c.Resolve(context.Background(), "abc")
	if err != nil || got == nil || got.AccessToken != "t" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestSetCookieFromResponse(t *testing.T) {
	dst := make(http.Header)
	src := http.Header{"Set-Cookie": {"a=1", "b=2"}}
	SetCookieFromResponse(dst, src)
	if len(dst["Set-Cookie"]) != 2 {
		t.Fatal(dst)
	}
}
