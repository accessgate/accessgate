package policy

import (
	"testing"

	asTesting "github.com/accessgate/accessgate/internal/testutil"
)

func TestInputWithPrincipalAndHeaders(t *testing.T) {
	principal := asTesting.NewTestPrincipal("user-123")

	in := Input{
		Protocol:         "http",
		Method:           "GET",
		Path:             "/foo",
		GraphQLOperation: "QueryFoo",
		GRPCService:      "svc.Foo",
		GRPCMethod:       "Bar",
		Principal:        principal,
		Headers: map[string]string{
			"X-Test": "1",
		},
	}

	if in.Principal == nil || in.Principal.Subject != "user-123" {
		t.Fatalf("expected principal with subject user-123, got %#v", in.Principal)
	}
	if got := in.Headers["X-Test"]; got != "1" {
		t.Fatalf("expected header X-Test=1, got %q", got)
	}
}
