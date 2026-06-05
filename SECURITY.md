# Security Policy

AccessGate is an authentication and authorization runtime, so security is
core to the project. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of:

- GitHub's **[Private vulnerability reporting](https://github.com/accessgate/accessgate/security/advisories/new)**
  (Security tab → "Report a vulnerability"), or
- email the maintainers at the security contact listed on the organization profile.

Please include: affected component (`accessgate-auth`, `accessgate-proxy`, a
`pkg/`/`internal/` package, a plugin, or a config surface), version/commit,
reproduction steps or a proof of concept, and the impact you believe it has.

We aim to acknowledge reports within a few business days and to keep you updated
as we investigate and remediate. Please allow a reasonable disclosure window
before any public discussion.

## Scope

In scope: the core runtime (`cmd/`, `internal/`, `pkg/`), the policy engines
(Rego/WASM and signed bundle loading), the plugin host/API, and the shipped
example configurations as they pertain to safe defaults.

Out of scope: vulnerabilities in third-party identity providers, in your own
Rego/WASM policies, or in deployment infrastructure you control.

## Supported versions

AccessGate is under active development and APIs may evolve between minor
releases. Security fixes target the latest released minor and `main`. Pin a
released version for production and track release notes.

## Operational hardening recommendations

These reduce risk when running AccessGate:

- **Transport**: terminate everything over HTTPS; restrict OIDC callback/redirect URLs.
- **Sessions/cookies**: set `Secure`, `HttpOnly`, an appropriate `SameSite`, and a
  scoped cookie domain; use a strong `cookie_signing_secret` from a secret manager.
- **Secrets**: never commit IdP client secrets or signing secrets; load them from
  environment/secret management. Do **not** embed credentials in git remote URLs.
- **Policy**: keep the fail-closed default (`policy_fallback_allow` unset/false) so a
  missing or failed policy denies rather than allows. Sign WASM bundles
  (`bundle_public_key_path`) and verify them.
- **Upstreams**: set explicit upstream allowlists and timeouts.
- **Headers**: AccessGate strips CR/LF from obligation-derived headers to prevent
  header injection — keep this behavior; review custom `HeaderBuilder`s for the same.
- **Observability**: monitor the `accessgate_*` Prometheus metrics (e.g. auth
  decision counts) and enable tracing for incident response.

## Credential hygiene

If a token or secret is ever exposed (for example, committed to a repo or embedded
in a git remote URL), rotate it immediately: revoke the credential at the provider,
issue a replacement with least privilege, and scrub it from configuration and
remotes. CI scans (`govulncheck`, CodeQL) supplement — but do not replace — these
practices.
