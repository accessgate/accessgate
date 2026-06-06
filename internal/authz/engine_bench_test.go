package authz

import (
	"context"
	"net/http"
	"testing"

	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/pkg/token"
)

// benchResolver is a deterministic stub PrincipalResolver: it returns a fixed
// principal without touching network/session stores, so the benchmark measures
// only the engine's decision path.
type benchResolver struct {
	principal *token.Principal
}

func (r benchResolver) Resolve(_ context.Context, _ *Request) (*token.Principal, error) {
	return r.principal, nil
}

// benchPolicy is a deterministic in-memory policy engine returning a fixed
// decision. It avoids Rego/WASM compilation so the engine hot path is isolated.
type benchPolicy struct {
	decision *policy.Decision
}

func (p benchPolicy) Evaluate(_ context.Context, _ policy.Input) (*policy.Decision, error) {
	// Return a copy so callers that mutate Headers don't corrupt the fixture.
	d := *p.decision
	return &d, nil
}

// benchPrincipal is a representative principal with roles and claims so the
// default header builder does meaningful work on the allow path.
func benchPrincipal() *token.Principal {
	return &token.Principal{
		Subject:     "user-123",
		Roles:       []string{"admin", "editor"},
		AccessToken: "redacted-access-token",
		Claims: map[string]any{
			"email":              "user@example.com",
			"name":               "Example User",
			"preferred_username": "example",
		},
		TenantContext: map[string]any{"tenant_id": "tenant-1"},
	}
}

func benchRequest() *Request {
	return &Request{
		Protocol: "http",
		Method:   "GET",
		Path:     "/api/v1/resource",
		Headers: map[string]string{
			"Accept":     "application/json",
			"User-Agent": "bench/1.0",
		},
	}
}

// BenchmarkEngineHandle_Allow measures the full DefaultEngine.Handle decision
// path for an allowed request: principal resolve -> policy eval -> header build.
func BenchmarkEngineHandle_Allow(b *testing.B) {
	e := &DefaultEngine{
		Resolver:    benchResolver{principal: benchPrincipal()},
		Policy:      benchPolicy{decision: &policy.Decision{Allow: true, StatusCode: http.StatusOK}},
		RequireAuth: true,
	}
	req := benchRequest()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := e.Handle(ctx, req)
		if err != nil || !resp.Allow {
			b.Fatalf("unexpected result: resp=%#v err=%v", resp, err)
		}
	}
}

// BenchmarkEngineHandle_Deny measures the decision path when the policy denies
// the request (reason-bearing JSON body is constructed).
func BenchmarkEngineHandle_Deny(b *testing.B) {
	e := &DefaultEngine{
		Resolver: benchResolver{principal: benchPrincipal()},
		Policy: benchPolicy{decision: &policy.Decision{
			Allow:      false,
			StatusCode: http.StatusForbidden,
			Reason:     "denied by policy",
		}},
		RequireAuth: true,
	}
	req := benchRequest()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := e.Handle(ctx, req)
		if err != nil || resp.Allow {
			b.Fatalf("unexpected result: resp=%#v err=%v", resp, err)
		}
	}
}
