# ADR-0002: Split auth lifecycle and request-time enforcement into two services

- **Status**: Accepted
- **Date**: 2026-06-05

## Context

AccessGate has two very different jobs. One is the **identity lifecycle**: browser-facing
OIDC login/callback/refresh/logout, talking to the IdP, holding secrets (client secret,
cookie signing key), and managing server-side session state in Redis. The other is
**request-time enforcement**: a hot path that runs on every protected request and must be
fast, horizontally scalable, and minimal in attack surface.

Combining them in one process would force the enforcement hot path to carry IdP clients,
Redis connections, and secrets it does not strictly need, and would couple the scaling and
deployment of two workloads with different profiles.

## Decision

We ship two binaries:

- **`accessgate-auth`** (`cmd/accessgate-auth/main.go`) owns the full auth lifecycle —
  OIDC + PKCE, JWKS validation, signed cookies, and the Redis-backed session, PKCE, and
  refresh-lock stores. It is the only service that holds IdP credentials and the cookie
  signing secret.
- **`accessgate-proxy`** (`cmd/accessgate-proxy/main.go`) owns enforcement — principal
  resolution, pipeline plugins, policy evaluation, and decision-to-header mapping.

They communicate over HTTP. The proxy never reads Redis or calls the IdP directly. Instead,
its `AuthPrincipalResolver` (`internal/proxy/resolver.go`) calls `accessgate-auth` at
`GET /internal/resolve` (`internal/proxy/authclient.go`), passing the session cookie. The
auth service decodes the signed cookie, loads the session from Redis, and returns
`{ access_token, claims, tenant_context }`, which the proxy turns into a `token.Principal`.
A `401` from that endpoint simply means "no principal."

(`accessgate-auth` also exposes a browser-facing `GET /session` for front ends to read the
current user; the proxy uses the dedicated internal resolve endpoint because it additionally
needs the access token and tenant context.)

## Consequences

- Each service scales and deploys independently: the proxy can run many lightweight replicas
  on the hot path while auth scales with login/refresh traffic.
- Secrets and Redis are confined to `accessgate-auth`, shrinking the proxy's attack surface
  and blast radius.
- The `/internal/resolve` HTTP contract becomes a stable internal boundary that both
  services must honor.
- Cost: enforcement adds a network hop to auth per request. This is mitigated by the auth
  client timeout and by fail-closed handling (a resolve error yields `502`), but it means
  auth availability is on the request critical path and should be deployed accordingly
  (co-located, low-latency, redundant).
