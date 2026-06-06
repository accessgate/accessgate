# AccessGate local quickstart (docker compose)

Bring up a complete AccessGate stack locally and see a real allow/deny decision
through the proxy in under five minutes — no external IdP, no cloud account.

## What you get

| Service            | Role                                                      | Port (host) |
| ------------------ | --------------------------------------------------------- | ----------- |
| `accessgate-proxy` | Policy-enforcing reverse proxy — **the URL you curl**     | `8081`      |
| `accessgate-auth`  | Session / OIDC login service                              | `8080`      |
| `mockidp`          | In-repo mock OIDC issuer (`cmd/mockidp`) — local IdP      | `8082`      |
| `redis`            | Session + PKCE store for `accessgate-auth`                | (internal)  |
| `upstream`         | Sample protected backend ([httpbin]) the proxy forwards to | (internal)  |

Images are built from the committed multi-stage Dockerfiles in
`../../build/docker` (distroless, non-root, static — ADR-0005).

## 1. Start the stack

```sh
cd deployments/docker
cp .env.example .env          # the only required value is COOKIE_SIGNING_SECRET
docker compose up -d --build  # first build compiles the Go services (~1–2 min)
```

Wait until every service is healthy:

```sh
docker compose ps
```

`accessgate-proxy` and `accessgate-auth` report `(healthy)` once their built-in
`/healthz` check passes.

## 2. See an allow and a deny (no login required)

By default the proxy runs with `REQUIRE_AUTH=false`, so the sample policy alone
decides each request. The sample policy
([`policy/sample.rego`](./policy/sample.rego)) **allows `GET /anything/allow`**
and **denies everything else** (deny-by-default).

```sh
# ALLOW → 200, proxied to the upstream (httpbin echoes the request)
curl -i http://localhost:8081/anything/allow

# DENY (explicit) → 403, short-circuited by the policy (never reaches upstream)
curl -i http://localhost:8081/anything/deny

# DENY (default) → 403
curl -i http://localhost:8081/anything/secret
```

Observed output:

```text
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/allow
200
$ curl -s -w "\n%{http_code}\n" http://localhost:8081/anything/deny
{"errors":[{"message":"denied by sample policy"}]}
403
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/secret
403
```

The `200` body is httpbin's echo of the forwarded request — proof the proxy
allowed it and forwarded it to the upstream. The `403` is produced by the proxy
itself; the request never reaches the upstream.

### Editing the policy

`policy/` is bind-mounted read-only into the proxy. Edit
`policy/sample.rego`, then:

```sh
docker compose restart accessgate-proxy
```

The policy contract (see `internal/policy/rego.go`): declare
`package accessgate`, and define `decision` (the proxy evaluates
`data.accessgate.decision`). Input field names are the Go struct fields from
`internal/policy.Input` — capitalized, e.g. `input.Path`, `input.Method`,
`input.Principal`.

## 3. Require authentication (optional)

Flip the proxy to also require a logged-in session:

```sh
REQUIRE_AUTH=true docker compose up -d accessgate-proxy
```

Now an unauthenticated request to an otherwise-allowed path is rejected before
policy evaluation:

```sh
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/allow
401
```

### Log in via the mock IdP to get a session

The mock IdP auto-approves the login (it is a test issuer), so a single browser
visit or a cookie-following curl completes the whole OIDC code+PKCE flow:

```sh
# Drives /login → mockidp /authorize → /callback, storing the session cookie.
curl -s -c cookies.txt -b cookies.txt -L "http://localhost:8080/login?redirect=/" -o /dev/null
grep ess_session cookies.txt    # the __Host-ess_session cookie was minted
```

(In a browser: open <http://localhost:8080/login> — you are redirected through
`mockidp` and back, and the session cookie is set on `localhost`.)

Replay the demo with the session cookie against the proxy:

```sh
$ curl -s -b cookies.txt -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/allow
200
$ curl -s -b cookies.txt -o /dev/null -w "%{http_code}\n" http://localhost:8081/anything/deny
403
```

With a valid session the proxy resolves the principal, then the policy decides:
`allow` → `200`, `deny` → `403`.

Switch back to the no-login demo at any time:

```sh
docker compose up -d accessgate-proxy   # REQUIRE_AUTH defaults to false
```

## 4. Tear down

```sh
docker compose down          # stop and remove containers + network
docker compose down -v       # also drop the (ephemeral) redis data
```

## Configuration notes

- All service config comes from environment variables (see
  `docker-compose.yml` and `.env.example`); keys are the UPPER_SNAKE_CASE form
  of the config keys documented in `../../docs/CONFIG-KEYS.md`.
- `ALLOW_PRIVATE_UPSTREAMS=true` is set on the proxy because the upstream runs
  on a private docker-network address. This relaxes AccessGate's SSRF guard and
  is **only** acceptable for local development.
- `COOKIE_SECURE=false` lets the session cookie work over plain HTTP locally.
  Production must serve over HTTPS with `COOKIE_SECURE=true`.
- Every value in `.env.example` is a local-only default. Do not reuse any of
  them outside local development.

[httpbin]: https://httpbin.org/
