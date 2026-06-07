# accessgate-proxy

The request-time enforcement proxy of [AccessGate](https://github.com/accessgate/accessgate) —
an identity-aware proxy for OIDC authentication and policy-based authorization.
`accessgate-proxy` resolves the caller's identity, evaluates policy (Rego or
signed WASM bundles), and forwards allowed requests upstream with
identity-derived headers; its sibling image
[`accessgate-auth`](https://hub.docker.com/r/accessgate/accessgate-auth) owns
the OIDC login lifecycle.

Multi-arch (`linux/amd64`, `linux/arm64`), distroless, non-root. Published on
every tagged release to Docker Hub and to GHCR (canonical:
`ghcr.io/accessgate/accessgate-proxy`). Images are keyless-signed with cosign
and carry SLSA build provenance — see
[verification docs](https://github.com/accessgate/accessgate/blob/main/docs/RELEASING.md).

```sh
docker pull accessgate/accessgate-proxy:latest
```

Quickstart (compose stack with both services, Redis, a mock IdP, and a sample
policy): see the
[repository README](https://github.com/accessgate/accessgate#quickstart).

Source, docs, issues: https://github.com/accessgate/accessgate · Apache-2.0
