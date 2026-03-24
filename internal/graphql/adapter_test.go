package graphql

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeHTTPRequestNotImplemented(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	_, err := NormalizeHTTPRequest(r)
	if err == nil {
		t.Fatal("expected error")
	}
}
