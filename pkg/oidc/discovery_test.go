package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryAndAuthURL(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(Discovery{
			Issuer:                srv.URL,
			AuthorizationEndpoint: srv.URL + "/auth",
			TokenEndpoint:         srv.URL + "/token",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "cid", "sec", "https://cb", []string{"openid"}, "aud")
	d, err := c.Discovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.TokenEndpoint == "" {
		t.Fatal("empty token endpoint")
	}

	u, err := c.AuthURL(ctx, "state", "challenge", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "code_challenge=challenge") || !strings.Contains(u, "state=state") {
		t.Fatalf("auth url: %s", u)
	}
	if !strings.Contains(u, "audience=aud") {
		t.Fatalf("expected audience: %s", u)
	}
}

func TestFetchDiscoveryBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "c", "", "https://cb", nil, "")
	_, err := c.Discovery(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchDiscoveryMissingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Discovery{Issuer: "x"})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "c", "", "https://cb", nil, "")
	_, err := c.Discovery(context.Background())
	if err == nil {
		t.Fatal("expected error for missing endpoints")
	}
}
