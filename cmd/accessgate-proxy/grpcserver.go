package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	authz "github.com/accessgate/accessgate/internal/authz"
	agrpc "github.com/accessgate/accessgate/internal/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// rawCodecName is the name under which the pass-through byte codec registers.
const rawCodecName = "accessgate-raw-bytes"

// rawCodec is a pass-through codec that marshals/unmarshals raw byte slices. It
// lets the proxy forward arbitrary gRPC methods to an upstream without any
// knowledge of the concrete protobuf message types: the wire bytes received from
// the client are handed to the upstream verbatim and vice versa.
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
	// Copy: the gRPC transport may reuse the underlying buffer after Unmarshal
	// returns, and the forwarded frame outlives this call.
	buf := make([]byte, len(data))
	copy(buf, data)
	*p = buf
	return nil
}

func (rawCodec) Name() string { return rawCodecName }

func init() {
	// Register the raw codec globally so the upstream ClientStream can resolve it
	// by name (gRPC's content-subtype lookup uses the global registry). The server
	// side forces it explicitly via grpc.ForceServerCodec.
	encoding.RegisterCodec(rawCodec{})
}

// upstreamForwarder holds a lazily-dialed shared client connection to the
// upstream gRPC backend and proxies authorized calls to it using the raw codec.
type upstreamForwarder struct {
	addr     string
	insecure bool

	mu   sync.Mutex
	conn *grpc.ClientConn
}

// newUpstreamForwarder constructs a forwarder for the given upstream address.
// The connection is dialed lazily on first use (and reused thereafter).
func newUpstreamForwarder(addr string, insecureTransport bool) *upstreamForwarder {
	return &upstreamForwarder{addr: addr, insecure: insecureTransport}
}

// clientConn returns the shared upstream connection, dialing it once on first
// use. grpc.NewClient does not establish a TCP connection eagerly, so dial
// failures surface on the first RPC and are mapped to codes.Unavailable.
func (f *upstreamForwarder) clientConn() (*grpc.ClientConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return f.conn, nil
	}
	var creds credentials.TransportCredentials
	if f.insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewClientTLSFromCert(nil, "")
	}
	conn, err := grpc.NewClient(f.addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		return nil, err
	}
	f.conn = conn
	return f.conn, nil
}

// Close tears down the shared upstream connection (called on shutdown).
func (f *upstreamForwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn == nil {
		return nil
	}
	err := f.conn.Close()
	f.conn = nil
	return err
}

// director is the gRPC UnknownServiceHandler used when forwarding is enabled. It
// is invoked for every authorized method (the authz interceptors run first and
// short-circuit denied calls). It opens a streaming client call to the upstream
// for the same full method and pipes messages in both directions, handling both
// unary and streaming RPCs uniformly (a unary RPC is a stream with exactly one
// message in each direction).
func (f *upstreamForwarder) director(_ any, serverStream grpc.ServerStream) error {
	fullMethod, ok := grpc.MethodFromServerStream(serverStream)
	if !ok {
		return status.Error(codes.Internal, "accessgate-proxy: could not determine method for forwarding")
	}

	conn, err := f.clientConn()
	if err != nil {
		return status.Errorf(codes.Unavailable, "accessgate-proxy: upstream dial failed: %v", err)
	}

	// Build the outbound context: start from the incoming metadata so the upstream
	// sees the client's headers, then overlay the authz identity headers as
	// lowercase gRPC metadata keys (gRPC lowercases keys on the wire regardless).
	outCtx := f.outgoingContext(serverStream.Context(), serverStream)

	// Open the upstream stream. The bidirectional stream descriptor lets us pipe
	// any RPC kind; the raw codec passes frames through untouched.
	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}
	clientCtx, clientCancel := context.WithCancel(outCtx)
	defer clientCancel()

	upstreamStream, err := conn.NewStream(clientCtx, desc, fullMethod, grpc.ForceCodec(rawCodec{}))
	if err != nil {
		return status.Errorf(codes.Unavailable, "accessgate-proxy: upstream stream failed: %v", err)
	}

	// Pipe client -> upstream and upstream -> client concurrently. The
	// upstream->client copier returns the authoritative RPC error/status.
	//
	// Both copiers report on buffered channels so neither goroutine leaks even if
	// we stop reading: the c2u goroutine that may still be blocked on the
	// downstream client's RecvMsg is unblocked when this director returns and the
	// server tears the inbound stream down (its context is cancelled).
	c2u := forwardClientToUpstream(serverStream, upstreamStream)
	u2c := forwardUpstreamToClient(upstreamStream, serverStream)

	// The upstream->client direction is authoritative: it completes when the
	// upstream returns its final status (success on io.EOF, or an error carrying
	// the upstream gRPC status). We wait for it, then surface a client->upstream
	// transport error only if the upstream itself ended cleanly.
	upstreamErr := <-u2c

	// Propagate the upstream's trailers to our client regardless of outcome.
	serverStream.SetTrailer(upstreamStream.Trailer())

	if upstreamErr != nil {
		// upstreamErr already carries the upstream gRPC status; surface it verbatim.
		return upstreamErr
	}
	// Upstream ended cleanly; if the client->upstream pump hit a non-EOF transport
	// error that already completed, surface it. We never block on this channel:
	// for server-streaming/unary the client half-closes (EOF) so it is already
	// done; for long-lived client streams a still-pending pump is harmless and is
	// torn down when we return.
	select {
	case clientErr := <-c2u:
		if clientErr != nil && !errors.Is(clientErr, io.EOF) {
			return clientErr
		}
	default:
	}
	return nil
}

// outgoingContext builds the outbound metadata for the forwarded call from the
// incoming metadata plus the authz identity headers.
func (f *upstreamForwarder) outgoingContext(ctx context.Context, serverStream grpc.ServerStream) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	out := md.Copy()
	if out == nil {
		out = metadata.MD{}
	}
	for k, v := range agrpc.IdentityHeaders(serverStream) {
		// gRPC metadata keys are lowercased on the wire; do so explicitly so the
		// upstream sees deterministic keys (e.g. "x-user-id"). Set (replace) so the
		// proxy-injected identity wins over any client-supplied value.
		out.Set(strings.ToLower(k), v)
	}
	return metadata.NewOutgoingContext(ctx, out)
}

// forwardClientToUpstream copies messages from the downstream client to the
// upstream until the client half-closes (io.EOF), then closes the upstream send
// direction. It runs in its own goroutine and reports completion on the channel.
func forwardClientToUpstream(src grpc.ServerStream, dst grpc.ClientStream) chan error {
	ret := make(chan error, 1)
	go func() {
		for {
			var frame []byte
			if err := src.RecvMsg(&frame); err != nil {
				if errors.Is(err, io.EOF) {
					// Client half-closed: signal end-of-stream to the upstream.
					ret <- dst.CloseSend()
					return
				}
				ret <- err
				return
			}
			if err := dst.SendMsg(frame); err != nil {
				ret <- err
				return
			}
		}
	}()
	return ret
}

// forwardUpstreamToClient copies messages from the upstream back to the
// downstream client until the upstream returns its final status (io.EOF on a
// clean close, or an error carrying the upstream gRPC status). It runs in its
// own goroutine and reports the terminal error on the channel.
func forwardUpstreamToClient(src grpc.ClientStream, dst grpc.ServerStream) chan error {
	ret := make(chan error, 1)
	go func() {
		// The upstream's response header metadata must be forwarded before the
		// first message so client-side header reads observe it.
		if hdr, err := src.Header(); err == nil && len(hdr) > 0 {
			_ = dst.SetHeader(hdr)
		}
		for {
			var frame []byte
			if err := src.RecvMsg(&frame); err != nil {
				if errors.Is(err, io.EOF) {
					// Clean upstream completion: nil terminal status.
					ret <- nil
					return
				}
				// Non-EOF error carries the upstream gRPC status verbatim.
				ret <- err
				return
			}
			if err := dst.SendMsg(frame); err != nil {
				ret <- err
				return
			}
		}
	}()
	return ret
}

// newGRPCServer constructs the optional proxy gRPC server with the AccessGate
// authz interceptors installed. The returned server authorizes every incoming
// call through the shared engine.
//
// Forwarding model (terminate-authorize-forward): this server is an enforcement
// AND forwarding layer. It terminates the gRPC connection, runs the authz
// decision via the interceptors, and:
//   - when grpcUpstreamAddr is empty, returns codes.Unimplemented for any
//     authorized method (the legacy enforcement-only behavior); or
//   - when grpcUpstreamAddr is set, transparently forwards the authorized call
//     to the upstream gRPC backend via a raw-bytes codec director over a shared
//     grpc.ClientConn, injecting the authz identity headers as outbound metadata.
//
// When forwarding is enabled, the returned *upstreamForwarder is non-nil and the
// caller MUST Close() it on shutdown.
func newGRPCServer(engine authz.Engine, grpcUpstreamAddr string, grpcUpstreamInsecure bool) (*grpc.Server, *upstreamForwarder) {
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(agrpc.UnaryServerInterceptor(engine)),
		grpc.ChainStreamInterceptor(agrpc.StreamServerInterceptor(engine)),
	}

	var fwd *upstreamForwarder
	if grpcUpstreamAddr != "" {
		fwd = newUpstreamForwarder(grpcUpstreamAddr, grpcUpstreamInsecure)
		opts = append(opts,
			grpc.UnknownServiceHandler(fwd.director),
			// Force the raw codec server-side so received frames are delivered as
			// []byte to the director regardless of the client's content-subtype.
			grpc.ForceServerCodec(rawCodec{}),
		)
	} else {
		opts = append(opts, grpc.UnknownServiceHandler(unknownServiceHandler))
	}

	return grpc.NewServer(opts...), fwd
}

// unknownServiceHandler is invoked for any method once the authz interceptors
// have allowed the call, when forwarding is NOT configured. It returns a clear,
// intentional Unimplemented status because no upstream is set.
func unknownServiceHandler(_ interface{}, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	return status.Errorf(codes.Unimplemented,
		"accessgate-proxy authorized the call but no grpc_upstream_addr is configured for forwarding (method %q)", method)
}

// startGRPCServer binds a listener on addr and serves the gRPC server. The
// returned listener is closed by the caller (via the server's GracefulStop).
func startGRPCServer(srv *grpc.Server, addr string) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		// Serve returns ErrServerStopped on GracefulStop; the caller handles
		// shutdown sequencing, so we ignore that benign error here.
		_ = srv.Serve(lis)
	}()
	return lis, nil
}
