package grpc

import (
	"context"
	"testing"

	"github.com/accessgate/accessgate/internal/authz"
	gogrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testEngine struct{}

func (testEngine) Handle(_ context.Context, _ *authz.Request) (*authz.Response, error) {
	return &authz.Response{Allow: true}, nil
}

func TestUnaryServerInterceptorReturnsUnimplemented(t *testing.T) {
	engine := testEngine{}
	interceptor := UnaryServerInterceptor(engine)

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}

	info := &gogrpc.UnaryServerInfo{FullMethod: "/svc.Foo/Bar"}
	_, err := interceptor(context.Background(), "in", info, handler)
	if err == nil {
		t.Fatal("expected Unimplemented error from interceptor, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unimplemented {
		t.Fatalf("expected codes.Unimplemented, got %v", err)
	}
	if called {
		t.Fatal("handler must not be called by unimplemented interceptor")
	}
}

func TestStreamServerInterceptorReturnsUnimplemented(t *testing.T) {
	engine := testEngine{}
	interceptor := StreamServerInterceptor(engine)

	called := false
	handler := func(srv interface{}, ss gogrpc.ServerStream) error {
		called = true
		return nil
	}

	info := &gogrpc.StreamServerInfo{FullMethod: "/svc.Foo/Bar"}
	err := interceptor(nil, nil, info, handler)
	if err == nil {
		t.Fatal("expected Unimplemented error from stream interceptor, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unimplemented {
		t.Fatalf("expected codes.Unimplemented, got %v", err)
	}
	if called {
		t.Fatal("stream handler must not be called by unimplemented interceptor")
	}
}
