package authz

import (
	"encoding/json"
	"strings"

	"github.com/accessgate/accessgate/internal/graphql"
)

// NormalizeRequest builds a proxy Request from raw HTTP/gRPC data.
// Populates GraphQLOperation from body (operationName) or headers (X-Apollo-Operation-Name);
// populates GRPCService and GRPCMethod from :path or X-Grpc-* headers when present.
func NormalizeRequest(protocol, method, path string, headers, cookies map[string]string, body []byte) *Request {
	req := &Request{
		Protocol: protocol,
		Method:   method,
		Path:     path,
		Headers:  headers,
		Cookies:  cookies,
		Body:     body,
	}
	// GraphQL: operationName in JSON body or X-Apollo-Operation-Name header
	if name := headers["X-Apollo-Operation-Name"]; name != "" {
		req.GraphQLOperation = name
	}
	if req.GraphQLOperation == "" && len(body) > 0 {
		var gql struct {
			OperationName string `json:"operationName"`
		}
		if _ = json.Unmarshal(body, &gql); gql.OperationName != "" {
			req.GraphQLOperation = gql.OperationName
		}
	}
	// Fallback: when neither the header nor a JSON operationName supplied a
	// name, but the body is a raw GraphQL document (e.g. "query GetUser { ... }"),
	// extract the operation name (and type) directly from the document.
	if req.GraphQLOperation == "" && len(body) > 0 {
		if name, opType := graphql.ExtractOperation(body); name != "" || opType != "" {
			req.GraphQLOperation = name
			req.GraphQLOperationType = opType
		}
	}
	// gRPC: :path is like /package.Service/Method or X-Grpc-Service / X-Grpc-Method
	if svc := headers["X-Grpc-Service"]; svc != "" {
		req.GRPCService = svc
	}
	if meth := headers["X-Grpc-Method"]; meth != "" {
		req.GRPCMethod = meth
	}
	if req.GRPCService == "" && req.GRPCMethod == "" {
		if p := headers[":path"]; p != "" {
			// /package.Service/Method
			p = strings.TrimPrefix(p, "/")
			if idx := strings.LastIndex(p, "/"); idx >= 0 {
				req.GRPCService = p[:idx]
				req.GRPCMethod = p[idx+1:]
			}
		}
	}
	return req
}
