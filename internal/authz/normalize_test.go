package authz

import (
	"context"
	"net/http"
	"testing"

	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/pkg/token"
)

func TestNormalizeRequestPopulatesFields(t *testing.T) {
	req := NormalizeRequest(
		"http",
		"GET",
		"/foo",
		map[string]string{"X-Test": "1"},
		map[string]string{"cookie": "value"},
		[]byte("body"),
	)

	if req.Protocol != "http" || req.Method != "GET" || req.Path != "/foo" {
		t.Fatalf("unexpected basic fields: %#v", req)
	}
	if req.Headers["X-Test"] != "1" {
		t.Fatalf("expected header X-Test=1, got %q", req.Headers["X-Test"])
	}
	if req.Cookies["cookie"] != "value" {
		t.Fatalf("expected cookie value, got %q", req.Cookies["cookie"])
	}
	if string(req.Body) != "body" {
		t.Fatalf("expected body 'body', got %q", string(req.Body))
	}
}

func TestNormalizeRequestGraphQLOperationFromHeader(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/", map[string]string{
		"X-Apollo-Operation-Name": "GetUser",
	}, nil, nil)
	if req.GraphQLOperation != "GetUser" {
		t.Fatal(req.GraphQLOperation)
	}
}

func TestNormalizeRequestGraphQLOperationFromJSONBody(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/", nil, nil, []byte(`{"operationName":"ListItems"}`))
	if req.GraphQLOperation != "ListItems" {
		t.Fatal(req.GraphQLOperation)
	}
}

func TestNormalizeRequestGraphQLOperationFromRawQueryFallback(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/graphql", nil, nil, []byte(`query GetUser { user { id } }`))
	if req.GraphQLOperation != "GetUser" {
		t.Fatalf("expected GraphQLOperation GetUser from raw-query fallback, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "query" {
		t.Fatalf("expected GraphQLOperationType query, got %q", req.GraphQLOperationType)
	}
}

func TestNormalizeRequestRawGraphQLDoesNotOverrideHeader(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/graphql", map[string]string{
		"X-Apollo-Operation-Name": "FromHeader",
	}, nil, []byte(`query FromBody { user { id } }`))
	if req.GraphQLOperation != "FromHeader" {
		t.Fatalf("expected header to win, got %q", req.GraphQLOperation)
	}
}

func TestNormalizeRequestAnonymousRawGraphQL(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/graphql", nil, nil, []byte(`{ user { id } }`))
	if req.GraphQLOperation != "" {
		t.Fatalf("expected empty GraphQLOperation for anonymous op, got %q", req.GraphQLOperation)
	}
	if req.GraphQLOperationType != "query" {
		t.Fatalf("expected GraphQLOperationType query for shorthand, got %q", req.GraphQLOperationType)
	}
}

// capturingEngine records the policy.Input it was evaluated with.
type capturingEngine struct {
	got policy.Input
}

func (c *capturingEngine) Evaluate(_ context.Context, input policy.Input) (*policy.Decision, error) {
	c.got = input
	return &policy.Decision{Allow: true, StatusCode: http.StatusOK}, nil
}

// nilResolver resolves no principal (anonymous).
type nilResolver struct{}

func (nilResolver) Resolve(_ context.Context, _ *Request) (*token.Principal, error) {
	return nil, nil
}

// TestRawGraphQLFallbackReachesPolicyInput proves the raw-GraphQL fallback
// populates GraphQLOperation end-to-end into the policy input path.
func TestRawGraphQLFallbackReachesPolicyInput(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/graphql", nil, nil, []byte(`mutation CreateUser { createUser { id } }`))

	eng := &capturingEngine{}
	e := &DefaultEngine{
		Resolver:    nilResolver{},
		Policy:      eng,
		RequireAuth: false,
	}

	resp, err := e.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if !resp.Allow {
		t.Fatalf("expected allow, got %#v", resp)
	}
	if eng.got.GraphQLOperation != "CreateUser" {
		t.Fatalf("expected policy input GraphQLOperation CreateUser, got %q", eng.got.GraphQLOperation)
	}
}

func TestNormalizeRequestGRPCFromHeaders(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/", map[string]string{
		"X-Grpc-Service": "svc.Foo",
		"X-Grpc-Method":  "Bar",
	}, nil, nil)
	if req.GRPCService != "svc.Foo" || req.GRPCMethod != "Bar" {
		t.Fatalf("%#v", req)
	}
}

func TestNormalizeRequestGRPCFromPathPseudoHeader(t *testing.T) {
	req := NormalizeRequest("http", "POST", "/", map[string]string{
		":path": "/my.pkg.Service/Method",
	}, nil, nil)
	if req.GRPCService != "my.pkg.Service" || req.GRPCMethod != "Method" {
		t.Fatalf("%#v", req)
	}
}
