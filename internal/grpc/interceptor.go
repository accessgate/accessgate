package grpc

import (
	"context"

	"github.com/accessgate/accessgate/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// headersFromIncomingContext flattens incoming gRPC metadata into a
// case-preserving header map suitable for authz.Request.
//
// gRPC metadata keys are always lower-cased by the transport, and values are
// multi-valued. We join multiple values with a comma (per HTTP header
// semantics) and keep the first non-empty value otherwise. The original
// lower-cased key is preserved so policies can match consistently.
func headersFromIncomingContext(ctx context.Context) map[string]string {
	headers := make(map[string]string)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return headers
	}
	for k, vs := range md {
		if len(vs) == 0 {
			continue
		}
		joined := vs[0]
		for _, v := range vs[1:] {
			if v == "" {
				continue
			}
			if joined == "" {
				joined = v
				continue
			}
			joined += "," + v
		}
		headers[k] = joined
	}
	return headers
}

// buildRequest constructs an authz.Request for a gRPC call. The service and
// method are derived from the full method path; the gRPC :path pseudo-header is
// also populated so downstream normalization/policy logic that keys off :path
// continues to work.
func buildRequest(ctx context.Context, fullMethod string) *authz.Request {
	service, method := ExtractMethod(fullMethod)
	headers := headersFromIncomingContext(ctx)
	// Ensure the canonical pseudo-headers are present so policies can match on
	// either the structured fields or the raw header form.
	if _, ok := headers[":path"]; !ok {
		headers[":path"] = fullMethod
	}
	return &authz.Request{
		Protocol:    "grpc",
		Method:      "POST",
		Path:        fullMethod,
		Headers:     headers,
		GRPCService: service,
		GRPCMethod:  method,
	}
}

// statusFromResponse maps an authz deny Response to an appropriate gRPC status.
// HTTP 401 maps to Unauthenticated; everything else (403, 503, etc.) maps to
// PermissionDenied, which is the closest gRPC analogue for an authorization
// rejection.
func statusFromResponse(resp *authz.Response) error {
	code := codes.PermissionDenied
	msg := "request denied by accessgate policy"
	if resp != nil {
		switch resp.StatusCode {
		case 401:
			code = codes.Unauthenticated
			msg = "unauthenticated"
		case 403:
			code = codes.PermissionDenied
			msg = "permission denied"
		}
	}
	return status.Error(code, msg)
}

// UnaryServerInterceptor returns a unary interceptor that authorizes each call
// through the authz Engine before invoking the wrapped handler. When the engine
// denies the request, the call is rejected with an appropriate gRPC status and
// the handler is never invoked.
func UnaryServerInterceptor(engine authz.Engine) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		authzReq := buildRequest(ctx, info.FullMethod)
		resp, err := engine.Handle(ctx, authzReq)
		if err != nil {
			return nil, status.Error(codes.Internal, "authorization error")
		}
		if resp == nil || !resp.Allow {
			return nil, statusFromResponse(resp)
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a stream interceptor that authorizes each
// stream through the authz Engine before invoking the wrapped handler. The
// authorization decision is made once, at stream establishment, based on the
// invoking metadata. When denied, the stream handler is never invoked.
func StreamServerInterceptor(engine authz.Engine) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authzReq := buildRequest(ss.Context(), info.FullMethod)
		resp, err := engine.Handle(ss.Context(), authzReq)
		if err != nil {
			return status.Error(codes.Internal, "authorization error")
		}
		if resp == nil || !resp.Allow {
			return statusFromResponse(resp)
		}
		return handler(srv, ss)
	}
}
