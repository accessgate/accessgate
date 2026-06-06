package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/accessgate/accessgate/internal/authz"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeEngine is a configurable authz.Engine test double. It records the last
// request it received so tests can assert on service/method extraction.
type fakeEngine struct {
	resp    *authz.Response
	err     error
	lastReq *authz.Request
}

func (f *fakeEngine) Handle(_ context.Context, req *authz.Request) (*authz.Response, error) {
	f.lastReq = req
	return f.resp, f.err
}

// fakeServerStream is a minimal grpc.ServerStream carrying a context.
type fakeServerStream struct {
	gogrpc.ServerStream
	ctx context.Context
}

func (s fakeServerStream) Context() context.Context { return s.ctx }

func TestUnaryServerInterceptorAllow(t *testing.T) {
	engine := &fakeEngine{resp: &authz.Response{Allow: true}}
	interceptor := UnaryServerInterceptor(engine)

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-test", "1"))
	info := &gogrpc.UnaryServerInfo{FullMethod: "/svc.Foo/Bar"}
	out, err := interceptor(ctx, "in", info, handler)
	if err != nil {
		t.Fatalf("expected allow (nil error), got %v", err)
	}
	if !called {
		t.Fatal("handler must be called when allowed")
	}
	if out != "ok" {
		t.Fatalf("expected handler result, got %v", out)
	}
	if engine.lastReq == nil {
		t.Fatal("engine did not receive a request")
	}
	if engine.lastReq.GRPCService != "svc.Foo" || engine.lastReq.GRPCMethod != "Bar" {
		t.Fatalf("unexpected service/method: %q / %q", engine.lastReq.GRPCService, engine.lastReq.GRPCMethod)
	}
	if engine.lastReq.Headers["x-test"] != "1" {
		t.Fatalf("expected x-test header propagated, got %q", engine.lastReq.Headers["x-test"])
	}
}

func TestUnaryServerInterceptorDeny(t *testing.T) {
	cases := []struct {
		name     string
		resp     *authz.Response
		wantCode codes.Code
	}{
		{"forbidden", &authz.Response{Allow: false, StatusCode: 403}, codes.PermissionDenied},
		{"unauthenticated", &authz.Response{Allow: false, StatusCode: 401}, codes.Unauthenticated},
		{"generic deny", &authz.Response{Allow: false, StatusCode: 503}, codes.PermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := &fakeEngine{resp: tc.resp}
			interceptor := UnaryServerInterceptor(engine)

			called := false
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				called = true
				return "ok", nil
			}

			info := &gogrpc.UnaryServerInfo{FullMethod: "/svc.Foo/Bar"}
			_, err := interceptor(context.Background(), "in", info, handler)
			if err == nil {
				t.Fatal("expected deny error, got nil")
			}
			if st, ok := status.FromError(err); !ok || st.Code() != tc.wantCode {
				t.Fatalf("expected %v, got %v", tc.wantCode, err)
			}
			if called {
				t.Fatal("handler must not be called when denied")
			}
		})
	}
}

func TestUnaryServerInterceptorEngineError(t *testing.T) {
	engine := &fakeEngine{err: errors.New("boom")}
	interceptor := UnaryServerInterceptor(engine)

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &gogrpc.UnaryServerInfo{FullMethod: "/svc.Foo/Bar"}
	_, err := interceptor(context.Background(), "in", info, handler)
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Internal {
		t.Fatalf("expected codes.Internal on engine error, got %v", err)
	}
	if called {
		t.Fatal("handler must not be called on engine error")
	}
}

func TestStreamServerInterceptorAllow(t *testing.T) {
	engine := &fakeEngine{resp: &authz.Response{Allow: true}}
	interceptor := StreamServerInterceptor(engine)

	called := false
	handler := func(srv interface{}, ss gogrpc.ServerStream) error {
		called = true
		return nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-test", "1"))
	info := &gogrpc.StreamServerInfo{FullMethod: "/svc.Foo/Bar"}
	err := interceptor(nil, fakeServerStream{ctx: ctx}, info, handler)
	if err != nil {
		t.Fatalf("expected allow (nil error), got %v", err)
	}
	if !called {
		t.Fatal("stream handler must be called when allowed")
	}
	if engine.lastReq == nil || engine.lastReq.GRPCService != "svc.Foo" || engine.lastReq.GRPCMethod != "Bar" {
		t.Fatalf("unexpected request: %+v", engine.lastReq)
	}
}

func TestStreamServerInterceptorDeny(t *testing.T) {
	engine := &fakeEngine{resp: &authz.Response{Allow: false, StatusCode: 403}}
	interceptor := StreamServerInterceptor(engine)

	called := false
	handler := func(srv interface{}, ss gogrpc.ServerStream) error {
		called = true
		return nil
	}

	info := &gogrpc.StreamServerInfo{FullMethod: "/svc.Foo/Bar"}
	err := interceptor(nil, fakeServerStream{ctx: context.Background()}, info, handler)
	if err == nil {
		t.Fatal("expected deny error, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("expected codes.PermissionDenied, got %v", err)
	}
	if called {
		t.Fatal("stream handler must not be called when denied")
	}
}
