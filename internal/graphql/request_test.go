package graphql

import "testing"

func TestGraphQLRequestFields(t *testing.T) {
	req := GraphQLRequest{
		OperationName: "MyOperation",
	}
	if req.OperationName != "MyOperation" {
		t.Fatalf("expected OperationName MyOperation, got %q", req.OperationName)
	}
}
