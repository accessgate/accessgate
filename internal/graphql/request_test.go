package graphql

import "testing"

func TestGraphQLRequestFields(t *testing.T) {
	req := GraphQLRequest{
		OperationName: "MyOperation",
		OperationType: "query",
	}
	if req.OperationName != "MyOperation" {
		t.Fatalf("expected OperationName MyOperation, got %q", req.OperationName)
	}
	if req.OperationType != "query" {
		t.Fatalf("expected OperationType query, got %q", req.OperationType)
	}
}

func TestParseRequest(t *testing.T) {
	req := ParseRequest([]byte(`mutation DoThing { thing }`))
	if req.OperationName != "DoThing" {
		t.Fatalf("expected OperationName DoThing, got %q", req.OperationName)
	}
	if req.OperationType != "mutation" {
		t.Fatalf("expected OperationType mutation, got %q", req.OperationType)
	}
}
