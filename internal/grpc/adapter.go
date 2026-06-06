package grpc

import (
	"github.com/accessgate/accessgate/internal/authz"
)

// ToProxyRequest builds an authz.Request from gRPC metadata and method.
//
// The service/method are derived from the full method path via ExtractMethod;
// the provided headers and body are attached verbatim. The full method path is
// also recorded as the request Path so policies can match on it directly.
func ToProxyRequest(fullMethod string, headers map[string]string, body []byte) *authz.Request {
	svc, method := ExtractMethod(fullMethod)
	if headers == nil {
		headers = map[string]string{}
	}
	return &authz.Request{
		Protocol:    "grpc",
		Method:      "POST",
		Path:        fullMethod,
		GRPCService: svc,
		GRPCMethod:  method,
		Headers:     headers,
		Body:        body,
	}
}
