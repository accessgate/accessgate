package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/accessgate/accessgate/internal/authz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// policyEngine is a test authz.Engine that allows or denies based on the gRPC
// service/method it sees on the request. On allow it attaches an identity header
// (x-user-id) so forwarding tests can assert it reaches the upstream.
type policyEngine struct {
	allowMethod string
	userID      string
}

func (p policyEngine) Handle(_ context.Context, req *authz.Request) (*authz.Response, error) {
	if req.GRPCMethod == p.allowMethod {
		resp := &authz.Response{Allow: true}
		if p.userID != "" {
			resp.UpstreamHeaders = map[string]string{"X-User-Id": p.userID}
		}
		return resp, nil
	}
	return &authz.Response{Allow: false, StatusCode: 403}, nil
}

// dialAndInvoke makes a raw unary call to an arbitrary method and returns the
// resulting status code.
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
	// No upstream configured: authorized calls fall through to Unimplemented.
	srv, fwd := newGRPCServer(engine, "", false)
	if fwd != nil {
		t.Fatalf("expected nil forwarder when grpc_upstream_addr is empty")
	}

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
	// unknown-service handler which returns Unimplemented (no upstream set).
	if code := dialAndInvoke(t, addr, "/test.Svc/Allowed"); code != codes.Unimplemented {
		t.Fatalf("allowed method: expected Unimplemented (no upstream), got %v", code)
	}
}

// mockUpstream is an in-process gRPC server that echoes the request body and
// records the metadata it observed, using the raw codec (no proto stubs).
type mockUpstream struct {
	mu         sync.Mutex
	lastMD     metadata.MD
	calls      int
	echoSuffix []byte
}

// unaryEcho is the unknown-service handler for the mock upstream. It handles both
// unary and streaming calls by echoing every received frame back (with an
// optional suffix appended to the first frame) and recording the incoming
// metadata.
func (m *mockUpstream) handler(_ any, stream grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	m.mu.Lock()
	m.lastMD = md.Copy()
	m.calls++
	m.mu.Unlock()

	first := true
	for {
		var frame []byte
		if err := stream.RecvMsg(&frame); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		out := frame
		if first && len(m.echoSuffix) > 0 {
			out = append(append([]byte{}, frame...), m.echoSuffix...)
			first = false
		}
		if err := stream.SendMsg(out); err != nil {
			return err
		}
	}
}

func startMockUpstream(t *testing.T) (*mockUpstream, string) {
	t.Helper()
	m := &mockUpstream{echoSuffix: []byte("-echo")}
	srv := grpc.NewServer(
		grpc.UnknownServiceHandler(m.handler),
		grpc.ForceServerCodec(rawCodec{}),
	)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return m, lis.Addr().String()
}

func TestProxyGRPCForwardsAllowedUnary(t *testing.T) {
	upstream, upstreamAddr := startMockUpstream(t)

	engine := policyEngine{allowMethod: "Allowed", userID: "user-42"}
	srv, fwd := newGRPCServer(engine, upstreamAddr, true /* insecure */)
	if fwd == nil {
		t.Fatalf("expected non-nil forwarder when grpc_upstream_addr is set")
	}
	t.Cleanup(func() { _ = fwd.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var out []byte
	in := []byte("hello")
	if err := conn.Invoke(ctx, "/test.Svc/Allowed", in, &out, grpc.ForceCodec(rawCodec{})); err != nil {
		t.Fatalf("forwarded unary call failed: %v", err)
	}
	if string(out) != "hello-echo" {
		t.Fatalf("expected echoed body %q, got %q", "hello-echo", string(out))
	}

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.calls != 1 {
		t.Fatalf("expected upstream to see 1 call, got %d", upstream.calls)
	}
	got := upstream.lastMD.Get("x-user-id")
	if len(got) != 1 || got[0] != "user-42" {
		t.Fatalf("expected injected x-user-id=user-42 at upstream, got %v", got)
	}
}

func TestProxyGRPCDeniedNeverReachesUpstream(t *testing.T) {
	upstream, upstreamAddr := startMockUpstream(t)

	engine := policyEngine{allowMethod: "Allowed", userID: "user-42"}
	srv, fwd := newGRPCServer(engine, upstreamAddr, true)
	t.Cleanup(func() { _ = fwd.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	if code := dialAndInvoke(t, lis.Addr().String(), "/test.Svc/Denied"); code != codes.PermissionDenied {
		t.Fatalf("denied method: expected PermissionDenied, got %v", code)
	}

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if upstream.calls != 0 {
		t.Fatalf("denied call must not reach upstream; got %d calls", upstream.calls)
	}
}

func TestProxyGRPCForwardsStreaming(t *testing.T) {
	upstream, upstreamAddr := startMockUpstream(t)
	_ = upstream

	engine := policyEngine{allowMethod: "Stream", userID: "stream-user"}
	srv, fwd := newGRPCServer(engine, upstreamAddr, true)
	t.Cleanup(func() { _ = fwd.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}
	cs, err := conn.NewStream(ctx, desc, "/test.Svc/Stream", grpc.ForceCodec(rawCodec{}))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Send three frames, then half-close.
	frames := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	for _, f := range frames {
		if err := cs.SendMsg(f); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	// The mock echoes every frame (first one with -echo suffix).
	want := []string{"a-echo", "b", "c"}
	for i := range want {
		var out []byte
		if err := cs.RecvMsg(&out); err != nil {
			t.Fatalf("recv frame %d: %v", i, err)
		}
		if string(out) != want[i] {
			t.Fatalf("frame %d: expected %q, got %q", i, want[i], string(out))
		}
	}
	var trailing []byte
	if err := cs.RecvMsg(&trailing); err != io.EOF {
		t.Fatalf("expected EOF after stream, got %v (body %q)", err, string(trailing))
	}

	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	got := upstream.lastMD.Get("x-user-id")
	if len(got) != 1 || got[0] != "stream-user" {
		t.Fatalf("expected injected x-user-id=stream-user at upstream, got %v", got)
	}
}

func TestProxyGRPCUpstreamUnreachableMapsUnavailable(t *testing.T) {
	// Reserve a port and immediately close the listener so nothing is listening.
	lis0, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	deadAddr := lis0.Addr().String()
	_ = lis0.Close()

	engine := policyEngine{allowMethod: "Allowed", userID: "user-42"}
	srv, fwd := newGRPCServer(engine, deadAddr, true)
	t.Cleanup(func() { _ = fwd.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	if code := dialAndInvoke(t, lis.Addr().String(), "/test.Svc/Allowed"); code != codes.Unavailable {
		t.Fatalf("unreachable upstream: expected Unavailable, got %v", code)
	}
}
