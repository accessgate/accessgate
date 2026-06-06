package grpc

import (
	"google.golang.org/grpc"
)

// AuthorizedStream wraps a grpc.ServerStream and carries the AccessGate authz
// identity headers (resp.UpstreamHeaders) produced by the stream interceptor.
//
// The proxy's forwarding director (the gRPC UnknownServiceHandler) type-asserts
// the incoming stream to *AuthorizedStream to recover the identity headers and
// inject them as outbound gRPC metadata on the forwarded upstream call. Keeping
// the wrapper in this package lets the director live in package main while the
// interceptor (which owns the authz decision) stays here, without exporting the
// authz response type onto the wire.
type AuthorizedStream struct {
	grpc.ServerStream
	// UpstreamHeaders are the identity headers the authz engine built for this
	// authorized call (e.g. X-User-Id, Authorization). They are propagated to the
	// upstream as lowercase gRPC metadata keys by the director.
	UpstreamHeaders map[string]string
}

// NewAuthorizedStream wraps ss, attaching the authz identity headers. headers may
// be nil (no identity to propagate).
func NewAuthorizedStream(ss grpc.ServerStream, headers map[string]string) *AuthorizedStream {
	return &AuthorizedStream{ServerStream: ss, UpstreamHeaders: headers}
}

// IdentityHeaders returns the identity headers carried by the stream if it is an
// *AuthorizedStream, or nil otherwise. The director uses this to remain decoupled
// from the concrete wrapper type.
func IdentityHeaders(ss grpc.ServerStream) map[string]string {
	if as, ok := ss.(*AuthorizedStream); ok {
		return as.UpstreamHeaders
	}
	return nil
}
