package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRevokeNoEndpoint(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{
			AuthorizationEndpoint: srv.URL + "/auth",
			TokenEndpoint:         srv.URL + "/token",
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	if err := c.Revoke(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeSuccess(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(Discovery{
				AuthorizationEndpoint: srv.URL + "/auth",
				TokenEndpoint:         srv.URL + "/token",
				RevocationEndpoint:    srv.URL + "/revoke",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "sec", "https://cb", nil, "")
	if err := c.Revoke(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeErrorStatus(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(Discovery{
				AuthorizationEndpoint: srv.URL + "/auth",
				TokenEndpoint:         srv.URL + "/token",
				RevocationEndpoint:    srv.URL + "/revoke",
			})
			return
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("err"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	if err := c.Revoke(context.Background(), "t"); err == nil {
		t.Fatal("expected error")
	}
}
