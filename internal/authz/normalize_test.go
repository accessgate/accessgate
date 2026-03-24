package authz

import (
	"testing"
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
