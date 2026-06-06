package authz

import "testing"

// BenchmarkNormalizeRequest measures request normalization across the three
// shapes the parser handles: a GraphQL JSON body, a raw GraphQL document, and a
// gRPC :path pseudo-header. Each is a separate sub-benchmark so per-shape cost
// (notably JSON unmarshal vs document scan) is visible.
func BenchmarkNormalizeRequest(b *testing.B) {
	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		body    []byte
	}{
		{
			name:   "GraphQLJSONBody",
			method: "POST",
			path:   "/graphql",
			body:   []byte(`{"operationName":"ListItems","variables":{},"query":"query ListItems { items { id } }"}`),
		},
		{
			name:   "RawGraphQLDocument",
			method: "POST",
			path:   "/graphql",
			body:   []byte(`query GetUser { user { id name email } }`),
		},
		{
			name:    "GRPCPathPseudoHeader",
			method:  "POST",
			path:    "/",
			headers: map[string]string{":path": "/my.pkg.Service/Method"},
		},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = NormalizeRequest("http", c.method, c.path, c.headers, nil, c.body)
			}
		})
	}
}
