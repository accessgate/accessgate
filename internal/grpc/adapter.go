package grpc

import (
	"github.com/accessgate/accessgate/internal/authz"
)

// ToProxyRequest builds a authz.Request from gRPC metadata and method.
// TODO: implement; extract headers from metadata, set GRPCService/GRPCMethod from fullMethod.
func ToProxyRequest(fullMethod string, headers map[string]string, body []byte) *authz.Request {
	svc, method := ExtractMethod(fullMethod)
	return &authz.Request{
		GRPCService: svc,
		GRPCMethod:  method,
		Headers:     headers,
		Body:        body,
	}
}
