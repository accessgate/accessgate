# AccessGate Helm chart

Deploys the two AccessGate core services and a session store:

| Component          | Role                                                     | Image |
| ------------------ | -------------------------------------------------------- | ----- |
| `accessgate-proxy` | Policy-enforcing reverse proxy — **the entry point**     | `ghcr.io/accessgate/accessgate-proxy` |
| `accessgate-auth`  | OIDC session / login service                             | `ghcr.io/accessgate/accessgate-auth` |
| `redis` (subchart) | Session + PKCE store for `accessgate-auth`               | Bitnami Redis (bundled, optional) |

Both images are distroless and run non-root as uid **65532**; the chart sets a
matching pod/container `securityContext` (read-only root FS, all capabilities
dropped, `RuntimeDefault` seccomp).

This chart mirrors the configuration keys in
[`docs/CONFIG-KEYS.md`](../../../docs/CONFIG-KEYS.md): each setting under `auth`
and `proxy` maps to the matching `UPPER_SNAKE_CASE` environment variable. Empty
values fall back to the binary defaults; only the keys marked **required** below
must be supplied.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+ (OCI registry support; tested with Helm 4.2)
- Network access to `oci://registry-1.docker.io/bitnamicharts` to fetch the
  Redis subchart (only when `redis.enabled=true`).

## Fetch the Redis subchart

The Redis dependency is **not vendored** in source control. Resolve it once
(`Chart.lock` pins the version) before linting/installing:

```sh
helm dependency build deploy/helm/accessgate
```

## Quick start

`accessgate-auth` requires `OIDC_ISSUER`, `OIDC_REDIRECT_URI`, `OIDC_CLIENT_ID`,
`APP_BASE_URL`, and a cookie signing secret. `accessgate-proxy` requires
`UPSTREAM_URL`. A minimal install:

```sh
helm install accessgate deploy/helm/accessgate \
  --set-string secrets.create.cookieSigningSecret="$(openssl rand -hex 32)" \
  --set-string secrets.create.oidcClientSecret="<oidc-client-secret>" \
  --set-string auth.config.oidcIssuer="https://idp.example.com" \
  --set-string auth.config.oidcRedirectURI="https://app.example.com/callback" \
  --set-string auth.config.oidcClientID="accessgate" \
  --set-string auth.config.appBaseURL="https://app.example.com" \
  --set-string proxy.config.upstreamURL="https://upstream.example.com"
```

The proxy resolves `auth_url` to the in-cluster auth Service automatically; set
`proxy.config.authURL` to override.

## Secrets

Sensitive values are never placed in a ConfigMap. Provide them one of two ways:

1. **Chart-created Secret (default).** Set `secrets.create.*`. A Secret named
   `<release>-accessgate-secrets` is created and referenced via `secretKeyRef`.
   Supply real values at install time (`--set-string`, a private values file, or
   a sealed-secrets / SOPS workflow) — do not commit them.
2. **Existing Secret.** Set `secrets.existingSecret=<name>`; no Secret is
   created. It must contain the keys named by `secrets.secretKeys.*`:

   ```sh
   kubectl create secret generic my-accessgate-secrets \
     --from-literal=cookie-signing-secret="$(openssl rand -hex 32)" \
     --from-literal=oidc-client-secret="<oidc-client-secret>" \
     --from-literal=admin-secret="<admin-secret>"   # optional
   ```

| Value                 | Secret key (default)    | Env var                 | Required |
| --------------------- | ----------------------- | ----------------------- | -------- |
| Cookie signing secret | `cookie-signing-secret` | `COOKIE_SIGNING_SECRET` | **yes**  |
| OIDC client secret    | `oidc-client-secret`    | `OIDC_CLIENT_SECRET`    | no¹      |
| Admin secret          | `admin-secret`          | `ADMIN_SECRET`          | no       |

¹ Optional to the binary, but most real IdPs require it.

## Redis: bundled vs external / HA

`redis.enabled=true` (default) deploys the bundled Bitnami Redis subchart and
wires `accessgate-auth`'s `REDIS_URL` to `redis://<release>-redis-master:6379`.
Keys under `redis:` (other than `enabled`) pass through to the
[Bitnami chart](https://github.com/bitnami/charts/tree/main/bitnami/redis).

For an **external or HA Redis**, disable the subchart and point at your endpoint:

```sh
helm install accessgate deploy/helm/accessgate \
  --set redis.enabled=false \
  --set externalRedis.url="redis://my-redis:6379" \
  ...
```

Use `rediss://` for TLS. To pass credentials without putting them in the URL,
supply `REDIS_URL` yourself via `auth.extraEnv` (e.g. a `secretKeyRef`) and leave
`externalRedis.url` set to a non-secret placeholder, or embed credentials in the
URL with a private values file. See `docs/` for Redis HA guidance.

## Optional: proxy gRPC

The proxy can expose a gRPC listener and transparently forward authorized gRPC
calls to a backend (see [`docs/GUIDE-GRPC.md`](../../../docs/GUIDE-GRPC.md)):

```sh
  --set proxy.grpc.enabled=true \
  --set-string proxy.grpc.upstreamAddr="upstream:9090" \
  --set-string proxy.grpc.upstreamInsecure="true"   # dev/in-cluster plaintext
```

This adds `GRPC_LISTEN_ADDR` (default `:9091`) and a `grpc` port on the proxy
Service.

## Optional: inline policy bundle

Mount a Rego/WASM policy from values instead of baking it into the image:

```sh
  --set proxy.policyBundle.enabled=true \
  --set-string proxy.config.policyEngine=rego \
  --set-file proxy.policyBundle.content=./policy.rego \
  --set-string proxy.policyBundle.fileName=policy.rego
```

The content is written to a ConfigMap, mounted read-only at
`proxy.policyBundle.mountPath`, and `POLICY_BUNDLE_PATH` is set automatically.

## Key values

| Key | Default | Description |
| --- | --- | --- |
| `auth.image.repository` / `proxy.image.repository` | `ghcr.io/accessgate/accessgate-{auth,proxy}` | GHCR images |
| `auth.image.tag` / `proxy.image.tag` | `""` → `.Chart.AppVersion` | Image tag |
| `auth.replicaCount` / `proxy.replicaCount` | `2` | Replicas |
| `auth.config.*` / `proxy.config.*` | see `values.yaml` | Env-mapped config (CONFIG-KEYS.md) |
| `proxy.config.requireAuth` | `"false"` | Require an authenticated session |
| `proxy.config.allowPrivateUpstreams` | `"false"` | Relax SSRF guard (never in prod) |
| `redis.enabled` | `true` | Deploy bundled Redis subchart |
| `externalRedis.url` | `""` | External Redis URL (when `redis.enabled=false`) |
| `secrets.existingSecret` | `""` | Use an existing Secret instead of creating one |

See [`values.yaml`](./values.yaml) for the complete, commented set.

## Verify the chart

```sh
helm dependency build deploy/helm/accessgate
helm lint deploy/helm/accessgate
helm template deploy/helm/accessgate \
  --set-string secrets.create.cookieSigningSecret=test \
  --set-string auth.config.oidcIssuer=https://i \
  --set-string auth.config.oidcRedirectURI=https://r \
  --set-string auth.config.oidcClientID=c \
  --set-string auth.config.appBaseURL=https://a \
  --set-string proxy.config.upstreamURL=https://u
```

## Notes

- `COOKIE_SECURE` defaults to `"true"` (production HTTPS). Set
  `auth.config.cookieSecure="false"` only for plain-HTTP local testing.
- The chart sets `OIDC_SCOPES` only if `auth.config.oidcScopes` is non-empty;
  the env-only loader rejects a comma-separated scopes string, so leave it empty
  to take the built-in default `["openid","profile"]` (mount a config file to
  customise scopes).
