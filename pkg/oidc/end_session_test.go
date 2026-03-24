package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndSessionURLEmptyWhenNoEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{
			AuthorizationEndpoint: srv.URL + "/a",
			TokenEndpoint:         srv.URL + "/t",
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	u, err := c.EndSessionURL(context.Background(), "", "")
	if err != nil || u != "" {
		t.Fatalf("u=%q err=%v", u, err)
	}
}

func TestEndSessionURLWithParams(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{
			AuthorizationEndpoint: srv.URL + "/a",
			TokenEndpoint:         srv.URL + "/t",
			EndSessionEndpoint:    srv.URL + "/logout",
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	u, err := c.EndSessionURL(context.Background(), "hint", "https://app.example/cb")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "id_token_hint=hint") || !strings.Contains(u, "post_logout_redirect_uri=") {
		t.Fatalf("url: %s", u)
	}
}

func TestEndSessionURLInvalidRedirect(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{
			AuthorizationEndpoint: srv.URL + "/a",
			TokenEndpoint:         srv.URL + "/t",
			EndSessionEndpoint:    srv.URL + "/logout",
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	_, err := c.EndSessionURL(context.Background(), "", "javascript:alert(1)")
	if err == nil {
		t.Fatal("expected error")
	}
}
