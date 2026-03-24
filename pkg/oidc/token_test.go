package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeSuccess(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			_ = json.NewEncoder(w).Encode(Discovery{
				AuthorizationEndpoint: srv.URL + "/auth",
				TokenEndpoint:         srv.URL + "/token",
			})
		case r.URL.Path == "/token":
			if r.Method != http.MethodPost {
				t.Fatalf("method %s", r.Method)
			}
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "grant_type=authorization_code") {
				t.Fatalf("body %s", b)
			}
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "a", RefreshToken: "r", IDToken: "i", ExpiresIn: 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "cid", "secret", "https://cb", nil, "")
	tr, err := c.Exchange(ctx, "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "a" || tr.RefreshToken != "r" {
		t.Fatalf("%+v", tr)
	}
}

func TestExchangeErrorStatus(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(Discovery{
				AuthorizationEndpoint: srv.URL + "/auth",
				TokenEndpoint:         srv.URL + "/token",
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("no"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	_, err := c.Exchange(ctx, "c", "v")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRefreshSuccess(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			_ = json.NewEncoder(w).Encode(Discovery{
				AuthorizationEndpoint: srv.URL + "/auth",
				TokenEndpoint:         srv.URL + "/token",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "new"})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "cid", "", "https://cb", nil, "")
	tr, err := c.Refresh(ctx, "rt")
	if err != nil || tr.AccessToken != "new" {
		t.Fatalf("%v %+v", err, tr)
	}
}
