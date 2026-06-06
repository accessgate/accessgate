package grpc

import "strings"

// ExtractMethod splits a full gRPC method path into service and method.
//
// The full method is of the canonical form "/package.Service/Method" (as
// exposed by grpc-go in UnaryServerInfo.FullMethod / StreamServerInfo.FullMethod).
// For example, "/helloworld.Greeter/SayHello" yields:
//
//	service = "helloworld.Greeter"
//	method  = "SayHello"
//
// Malformed input is handled gracefully: a missing leading slash is tolerated,
// and inputs without a separating slash (or with empty components) return empty
// strings for the affected component rather than panicking.
func ExtractMethod(fullMethod string) (service, method string) {
	if fullMethod == "" {
		return "", ""
	}
	// Canonical form starts with a leading slash; tolerate its absence.
	trimmed := strings.TrimPrefix(fullMethod, "/")
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 {
		// No method separator — cannot reliably split. Treat the whole token as
		// the service so callers still have something to authorize on.
		return trimmed, ""
	}
	service = trimmed[:idx]
	method = trimmed[idx+1:]
	return service, method
}
