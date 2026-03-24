package grpc

import (
	"context"

	"github.com/ArmanAvanesyan/accessgate/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a unary interceptor that delegates to the proxy Engine.
// Not yet implemented — returns Unimplemented so callers cannot silently bypass authorization.
func UnaryServerInterceptor(_ authz.Engine) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (interface{}, error) {
		return nil, status.Error(codes.Unimplemented, "accessgate gRPC interceptor not implemented")
	}
}

// StreamServerInterceptor returns a stream interceptor that delegates to the proxy Engine.
// Not yet implemented — returns Unimplemented so callers cannot silently bypass authorization.
func StreamServerInterceptor(_ authz.Engine) grpc.StreamServerInterceptor {
	return func(_ interface{}, _ grpc.ServerStream, _ *grpc.StreamServerInfo, _ grpc.StreamHandler) error {
		return status.Error(codes.Unimplemented, "accessgate gRPC interceptor not implemented")
	}
}
