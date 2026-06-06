package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// rawCodec is a pass-through codec that marshals/unmarshals raw byte slices.
// It lets the test invoke arbitrary methods without generated proto stubs.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec: expected []byte, got %T", v)
	}
	return b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: expected *[]byte, got %T", v)
	}
	*p = data
	return nil
}

func (rawCodec) Name() string { return "raw-bytes-test" }

// policyEngine is a test authz.Engine that allows or denies based on the gRPC
// service/method it sees on the request.
type policyEngine struct {
	allowMethod string
}

func (p policyEngine) Handle(_ context.Context, req *authz.Request) (*authz.Response, error) {
	if req.GRPCMethod == p.allowMethod {
		return &authz.Response{Allow: true}, nil
	}
	return &authz.Response{Allow: false, StatusCode: 403}, nil
}

// dialAndInvoke makes a raw unary call to an arbitrary method and returns the
// resulting status code. Because no service is registered, an allowed call
// reaches the UnknownServiceHandler (Unimplemented), and a denied call is
// rejected by the interceptor (PermissionDenied) — letting us assert the
// authorization decision distinctly from forwarding behavior.
func dialAndInvoke(t *testing.T, addr, fullMethod string) codes.Code {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var out []byte
	err = conn.Invoke(ctx, fullMethod, []byte{}, &out, grpc.ForceCodec(rawCodec{}))
	st, _ := status.FromError(err)
	return st.Code()
}

func TestProxyGRPCServerAuthorizes(t *testing.T) {
	engine := policyEngine{allowMethod: "Allowed"}
	srv := newGRPCServer(engine)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	addr := lis.Addr().String()

	// Denied method: interceptor rejects with PermissionDenied before reaching
	// the unknown-service handler.
	if code := dialAndInvoke(t, addr, "/test.Svc/Denied"); code != codes.PermissionDenied {
		t.Fatalf("denied method: expected PermissionDenied, got %v", code)
	}

	// Allowed method: interceptor permits, call falls through to the
	// unknown-service handler which returns Unimplemented (forwarding not yet
	// implemented).
	if code := dialAndInvoke(t, addr, "/test.Svc/Allowed"); code != codes.Unimplemented {
		t.Fatalf("allowed method: expected Unimplemented from forwarding stub, got %v", code)
	}
}
