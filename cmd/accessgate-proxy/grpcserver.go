package main

import (
	"net"

	authz "github.com/accessgate/accessgate/internal/authz"
	agrpc "github.com/accessgate/accessgate/internal/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newGRPCServer constructs the optional proxy gRPC server with the AccessGate
// authz interceptors installed. The returned server authorizes every incoming
// call through the shared engine; authorized calls fall through to the
// UnknownServiceHandler.
//
// Forwarding model (terminate-and-authorize): this server is an enforcement
// layer. It terminates the gRPC connection, runs the authz decision via the
// interceptors, and — because transparent byte-level forwarding to an upstream
// gRPC backend is intentionally out of scope for this PR (see docs/GUIDE-GRPC.md)
// — returns codes.Unimplemented with a clear "forwarding not yet implemented"
// message for any authorized method. This guarantees the authorization path is
// correct and fully tested before a forwarding transport is added.
func newGRPCServer(engine authz.Engine) *grpc.Server {
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(agrpc.UnaryServerInterceptor(engine)),
		grpc.ChainStreamInterceptor(agrpc.StreamServerInterceptor(engine)),
		grpc.UnknownServiceHandler(unknownServiceHandler),
	)
	return srv
}

// unknownServiceHandler is invoked for any method once the authz interceptors
// have allowed the call. It returns a clear, intentional Unimplemented status
// because upstream forwarding is not yet implemented (see docs/GUIDE-GRPC.md).
func unknownServiceHandler(_ interface{}, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	return status.Errorf(codes.Unimplemented,
		"accessgate-proxy authorized the call but upstream gRPC forwarding is not yet implemented for %q", method)
}

// startGRPCServer binds a listener on addr and serves the gRPC server. The
// returned listener is closed by the caller (via the server's GracefulStop).
func startGRPCServer(srv *grpc.Server, addr string) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		// Serve returns ErrServerStopped on GracefulStop; the caller handles
		// shutdown sequencing, so we ignore that benign error here.
		_ = srv.Serve(lis)
	}()
	return lis, nil
}
