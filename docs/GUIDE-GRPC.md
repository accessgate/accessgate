# gRPC Authorization & Forwarding Guide

**Design note — terminate-authorize-forward model.** AccessGate's gRPC support is a
*terminate-authorize-forward* enforcement layer. The optional proxy gRPC server (enabled via
`grpc_listen_addr`) terminates each incoming gRPC connection, reconstructs a normalized
`authz.Request` from the call's full method (`/pkg.Service/Method`, split by
`internal/grpc.ExtractMethod`) and its incoming metadata, and runs it through the *same* shared
`authz.Engine` used by the HTTP/GraphQL path — so a single policy bundle governs every protocol.

When an upstream is configured (`grpc_upstream_addr`), authorized calls are **transparently
forwarded** to that upstream gRPC backend over a shared `grpc.ClientConn`, using a pass-through
raw-bytes codec so the proxy needs no knowledge of the concrete protobuf message types. When no
upstream is configured, authorized calls fall through to a `grpc.UnknownServiceHandler` that returns
`codes.Unimplemented` (the proxy then acts purely as an authorization gate in front of an in-process
service mounted via the interceptors). Denied calls are always rejected before any forwarding occurs
(fail-closed).

## How requests are authorized

1. The unary/stream interceptors (`internal/grpc.UnaryServerInterceptor` /
   `StreamServerInterceptor`) extract `(service, method)` from the call's full method and flatten
   incoming gRPC metadata into request headers (lower-cased keys; multi-value headers comma-joined).
   The full method is also recorded as `:path` and as the request `Path`.
2. The interceptor calls `Engine.Handle`. The engine resolves the principal, runs pipeline plugins,
   then evaluates the policy with `policy.Input{GRPCService, GRPCMethod, ...}`.
3. The decision is mapped to a gRPC status:
   - **allow** → the call is forwarded to the upstream (or, when no upstream is configured, reaches
     the `UnknownServiceHandler` which returns `Unimplemented`).
   - **deny, HTTP 401** → `codes.Unauthenticated`.
   - **deny, any other status** (403, 503, …) → `codes.PermissionDenied`.
   - **engine error** → `codes.Internal`.

## How forwarding works

When `grpc_upstream_addr` is set, the server installs a forwarding **director** as its
`UnknownServiceHandler` (so it handles every method without generated stubs):

- **Shared connection.** A single `grpc.ClientConn` to the upstream is dialed lazily on the first
  forwarded call and reused thereafter. It is dialed with TLS by default, or with an insecure
  (plaintext) transport when `grpc_upstream_insecure: true`. The connection is closed on shutdown.
- **Raw-bytes codec.** Both the server and the upstream client use a pass-through `[]byte` codec, so
  the wire frames received from the client are handed to the upstream verbatim and vice versa — no
  proto descriptors are required and arbitrary services/methods are supported.
- **Bidirectional piping.** The director opens a streaming client call to the upstream for the same
  full method and pipes frames in both directions concurrently via `RecvMsg`/`SendMsg`. This handles
  unary, server-streaming, client-streaming, and bidi RPCs uniformly (a unary RPC is simply a stream
  with one frame each way). The upstream's response headers and trailers are propagated back to the
  client, and the upstream's final status is surfaced verbatim.
- **Identity propagation.** The authz engine's `UpstreamHeaders` (e.g. `X-User-Id`, `Authorization`)
  are carried from the interceptor to the director via a `grpc.ServerStream` wrapper
  (`internal/grpc.AuthorizedStream`) and injected as **lowercase** outbound gRPC metadata on the
  forwarded call, overlaid on top of the client's incoming metadata.
- **Fail-closed transport errors.** If the upstream cannot be dialed or the stream cannot be opened,
  the call is mapped to `codes.Unavailable`.

## Enabling the proxy gRPC server

Set `grpc_listen_addr` to a `host:port` listen address, and optionally `grpc_upstream_addr` to enable
forwarding:

```json
{
  "grpc_listen_addr": ":9091",
  "grpc_upstream_addr": "upstream:9090",
  "grpc_upstream_insecure": false
}
```

An empty `grpc_listen_addr` (the default) disables the gRPC server; the proxy then runs HTTP-only.
An empty `grpc_upstream_addr` enables authorization-only mode: authorized calls return
`codes.Unimplemented`. `grpc_upstream_addr` is SSRF-validated at startup exactly like `upstream_url`
(loopback/private/link-local addresses are rejected unless `allow_private_upstreams: true`).

When enabled, the gRPC server runs alongside the HTTP server and shares its authz engine. On shutdown
it performs a `GracefulStop` bounded by the proxy's shutdown deadline (falling back to a hard `Stop`),
then closes the shared upstream connection.

## Using the interceptors in your own server

The interceptors are reusable outside the proxy. Install them on any `grpc.Server` to enforce
AccessGate policy on a service you host in-process:

```go
srv := grpc.NewServer(
    grpc.ChainUnaryInterceptor(agrpc.UnaryServerInterceptor(engine)),
    grpc.ChainStreamInterceptor(agrpc.StreamServerInterceptor(engine)),
)
```

The stream interceptor authorizes once at stream establishment based on the invoking metadata.
