package grpc

import "testing"

func TestExtractMethodStub(t *testing.T) {
	svc, method := ExtractMethod("/package.Service/Method")
	if svc != "" || method != "" {
		t.Fatalf("got %q %q (stub returns empty until implemented)", svc, method)
	}
}
