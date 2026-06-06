package adapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeHTTPRequestFromHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`query GetUser { user { id } }`))
	r.Header.Set("X-Apollo-Operation-Name", "FromHeader")

	req, err := NormalizeHTTPRequest(r)
	if err != nil {
		t.Fatalf("NormalizeHTTPRequest returned error: %v", err)
	}
	// Header takes precedence for the operation name; the type still comes
	// from parsing the body.
	if req.GraphQLOperation != "FromHeader" {
		t.Fatalf("expected GraphQLOperation FromHeader, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "query" {
		t.Fatalf("expected GraphQLOperationType query, got %q", req.GraphQLOperationType)
	}
}

func TestNormalizeHTTPRequestFromJSONBody(t *testing.T) {
	body := `{"operationName":"ListItems","query":"query ListItems { items { id } }"}`
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))

	req, err := NormalizeHTTPRequest(r)
	if err != nil {
		t.Fatalf("NormalizeHTTPRequest returned error: %v", err)
	}
	if req.GraphQLOperation != "ListItems" {
		t.Fatalf("expected GraphQLOperation ListItems, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "query" {
		t.Fatalf("expected GraphQLOperationType query, got %q", req.GraphQLOperationType)
	}
}

func TestNormalizeHTTPRequestFromRawQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`mutation CreateUser { createUser { id } }`))

	req, err := NormalizeHTTPRequest(r)
	if err != nil {
		t.Fatalf("NormalizeHTTPRequest returned error: %v", err)
	}
	if req.GraphQLOperation != "CreateUser" {
		t.Fatalf("expected GraphQLOperation CreateUser, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "mutation" {
		t.Fatalf("expected GraphQLOperationType mutation, got %q", req.GraphQLOperationType)
	}
}

func TestNormalizeHTTPRequestAnonymous(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{ user { id } }`))

	req, err := NormalizeHTTPRequest(r)
	if err != nil {
		t.Fatalf("NormalizeHTTPRequest returned error: %v", err)
	}
	if req.GraphQLOperation != "" {
		t.Fatalf("expected empty GraphQLOperation for anonymous op, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "query" {
		t.Fatalf("expected GraphQLOperationType query, got %q", req.GraphQLOperationType)
	}
}

func TestNormalizeHTTPRequestPreservesBasics(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`query Q { a }`))
	r.RemoteAddr = "203.0.113.7:5555"

	req, err := NormalizeHTTPRequest(r)
	if err != nil {
		t.Fatalf("NormalizeHTTPRequest returned error: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("expected method POST, got %q", req.Method)
	}
	if req.Path != "/graphql" {
		t.Fatalf("expected path /graphql, got %q", req.Path)
	}
	if req.RemoteAddr != "203.0.113.7:5555" {
		t.Fatalf("expected RemoteAddr preserved, got %q", req.RemoteAddr)
	}
}
