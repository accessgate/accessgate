package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testEngine struct{}

func (testEngine) Handle(_ context.Context, _ *Request) (*Response, error) {
	return &Response{Allow: true}, nil
}

func TestMiddlewareAllowWritesResponseWhenNoUpstream(t *testing.T) {
	engine := testEngine{}
	mw := Middleware(engine, "")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatalf("middleware should not call next when handling the request")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}
