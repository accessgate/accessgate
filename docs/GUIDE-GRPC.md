# gRPC Authorization Guide

**Design note — terminate-and-authorize (enforcement-first) model.** AccessGate's gRPC support
is built as a *terminate-and-authorize* layer rather than a fully transparent proxy. The optional
proxy gRPC server (enabled via `grpc_listen_addr`) terminates each incoming gRPC connection,
reconstructs a normalized `authz.Request` from the call's full method (`/pkg.Service/Method`, split
by `internal/grpc.ExtractMethod`) and its incoming metadata, and runs it through the *same* shared
`authz.Engine` used by the HTTP/GraphQL path — so a single policy bundle governs every protocol.
Authorized calls currently fall through to a `grpc.UnknownServiceHandler` that returns
`codes.Unimplemented` with a clear "forwarding not yet implemented" message; transparent byte-level
forwarding to an upstream gRPC backend (via a raw-bytes codec director over a shared
`grpc.ClientConn`) is intentionally deferred to a follow-up so that the authorization path can ship
correct, fully tested, and fail-closed before a forwarding transport is introduced. This favors a
working, verifiable enforcement layer over an ambitious-but-flaky end-to-end proxy.

## How requests are authorized

1. The unary/stream interceptors (`internal/grpc.UnaryServerInterceptor` /
   `StreamServerInterceptor`) extract `(service, method)` from the call's full method and flatten
   incoming gRPC metadata into request headers (lower-cased keys; multi-value headers comma-joined).
   The full method is also recorded as `:path` and as the request `Path`.
2. The interceptor calls `Engine.Handle`. The engine resolves the principal, runs pipeline plugins,
   then evaluates the policy with `policy.Input{GRPCService, GRPCMethod, ...}`.
3. The decision is mapped to a gRPC status:
   - **allow** → the wrapped handler runs (in the proxy server, this reaches the
     `UnknownServiceHandler`).
   - **deny, HTTP 401** → `codes.Unauthenticated`.
   - **deny, any other status** (403, 503, …) → `codes.PermissionDenied`.
   - **engine error** → `codes.Internal`.

## Enabling the optional proxy gRPC server

Set `grpc_listen_addr` in the proxy config to a `host:port` listen address:

```json
{
  "grpc_listen_addr": ":9091"
}
```

An empty value (the default) disables the gRPC server; the proxy then runs HTTP-only. When enabled,
the gRPC server runs alongside the HTTP server and shares its authz engine. On shutdown it performs a
`GracefulStop` bounded by the proxy's shutdown deadline (falling back to a hard `Stop`).

## Using the interceptors in your own server

The interceptors are reusable outside the proxy. Install them on any `grpc.Server` to enforce
AccessGate policy on a service you host in-process:

```go
srv := grpc.NewServer(
    grpc.ChainUnaryInterceptor(agrpc.UnaryServerInterceptor(engine)),
    grpc.ChainStreamInterceptor(agrpc.StreamServerInterceptor(engine)),
)
```

## Current limitation

Upstream forwarding is **not yet implemented**. Authorized methods on the proxy gRPC server return
`codes.Unimplemented`. Use the server today as an authorization gate in front of an in-process
service (via the interceptors), or wait for the forwarding transport in a follow-up change. The
stream interceptor authorizes once at stream establishment based on the invoking metadata.
