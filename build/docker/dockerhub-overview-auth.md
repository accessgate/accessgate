# accessgate-auth

The user-facing OIDC auth service of [AccessGate](https://github.com/accessgate/accessgate) —
an identity-aware proxy for OIDC authentication and policy-based authorization.
`accessgate-auth` owns the auth lifecycle (`/login`, `/callback`, `/refresh`,
`/logout`, `/session`) backed by Redis sessions and signed cookies; its sibling
image [`accessgate-proxy`](https://hub.docker.com/r/accessgate/accessgate-proxy)
enforces policy at request time.

Multi-arch (`linux/amd64`, `linux/arm64`), distroless, non-root. Published on
every tagged release to Docker Hub and to GHCR (canonical:
`ghcr.io/accessgate/accessgate-auth`). Images are keyless-signed with cosign and
carry SLSA build provenance — see
[verification docs](https://github.com/accessgate/accessgate/blob/main/docs/RELEASING.md).

```sh
docker pull accessgate/accessgate-auth:latest
```

Quickstart (compose stack with both services, Redis, a mock IdP, and a sample
policy): see the
[repository README](https://github.com/accessgate/accessgate#quickstart).

Source, docs, issues: https://github.com/accessgate/accessgate · Apache-2.0
