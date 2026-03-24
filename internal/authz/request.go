package authz

// Request is the normalized representation of an incoming request for proxy evaluation.
type Request struct {
	Protocol         string
	Method           string
	Path             string
	Headers          map[string]string
	Cookies          map[string]string
	Body             []byte
	GraphQLOperation string
	GRPCService      string
	GRPCMethod       string
	RemoteAddr       string // TCP remote address (IP:port) — used by rate-limiter trusted-proxy logic
}
