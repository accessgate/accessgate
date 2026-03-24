# Gateway adapter example configs

Example configurations for using AccessGate with Caddy, Traefik, and KrakenD. All adapters call the same proxy/policy/token runtime.

- **caddy.Caddyfile** — Caddy using `forward_auth` to accessgate-proxy; optional AccessGate directive when building with `-tags caddy`.
- **caddy.example.json** — Config shape for the Caddy adapter (`auth_url`, `upstream_url`, `require_auth`).
- **traefik.example.yaml** — Traefik dynamic config with ForwardAuth middleware.
- **krakend.example.json** — KrakenD endpoint/auth plugin config (endpoint, `upstream_url`, `require_auth`).

See your organization’s integration documentation for full guides and compatibility notes.
