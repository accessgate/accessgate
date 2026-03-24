package grpc

import "testing"

func TestToProxyRequestUsesHeadersAndBody(t *testing.T) {
	headers := map[string]string{"X-Test": "1"}
	body := []byte("payload")

	req := ToProxyRequest("/svc.Foo/Bar", headers, body)
	if req == nil {
		t.Fatal("expected non-nil authz.Request")
	}
	if req.Headers["X-Test"] != "1" {
		t.Fatalf("expected header X-Test=1, got %q", req.Headers["X-Test"])
	}
	if string(req.Body) != "payload" {
		t.Fatalf("expected body payload, got %q", string(req.Body))
	}
}
