# Guide: Authoring Plugin Manifests

AccessGate can discover plugin instances from JSON **manifests** on the filesystem. A
manifest is a static description of a plugin: its identity, kind, the capabilities it
provides, and the capabilities it depends on. At startup the proxy walks the configured
manifest directory, validates each manifest, optionally verifies its signature, registers
it, and assembles a dependency-ordered startup graph.

This guide covers the manifest schema, the validation rules, strict mode, optional
signing, and a testing checklist.

## Where manifests live

Manifest discovery is enabled by setting `plugins_manifest_dir` in the proxy config to a
directory. Every `*.json` file under that directory (recursively) is treated as a manifest.
A missing directory is treated as "no plugins" (not an error).

Example manifests ship under [`configs/plugins/manifests/`](../configs/plugins/manifests/).

## Manifest schema

```json
{
  "id": "pipeline.ratelimit",
  "kind": "pipeline",
  "name": "Rate Limit",
  "description": "Token-bucket rate limiting pipeline plugin.",
  "version": "1.0.0",
  "capabilities": ["pipeline:ratelimit"],
  "depends_on": [],
  "config_schema_ref": "pipeline/ratelimit",
  "enabled": true,
  "metadata": {},
  "signature": {
    "algorithm": "ed25519",
    "value": "<base64-ed25519-signature>"
  }
}
```

### Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | **yes** | Stable, unique identifier for the plugin instance. Duplicate IDs are rejected. |
| `kind` | string | **yes** | One of the known kinds (see below). |
| `capabilities` | string[] | **yes** | Symbolic capability names the plugin provides. Must be non-empty; entries must be non-empty. |
| `name` | string | no | Human-readable name. |
| `description` | string | no | Human-readable description. |
| `version` | string | no | Plugin version. |
| `depends_on` | string[] | no | Capability names this plugin requires (see semantics below). Entries must be non-empty. |
| `config_schema_ref` | string | no | Reference to a JSON Schema under `schemas/plugins/**` (without the `.schema.json` suffix), e.g. `pipeline/ratelimit`. |
| `enabled` | bool | no | When `false`, the plugin is registered but disabled. Defaults to enabled. |
| `metadata` | object | no | Arbitrary plugin-specific metadata. |
| `signature` | object | no | Optional inline Ed25519 signature; see [Signing](#signing-optional). |

### Kinds

`kind` must be one of:

- `pipeline` — participates in the proxy request pipeline (e.g. rate limiting, header
  injection).
- `provider` — an identity provider integration (e.g. OIDC).
- `integration` — a gateway integration (e.g. Caddy, Traefik, KrakenD).

An unknown kind fails validation with a descriptive error naming the manifest path and id.

### Capabilities

Capabilities are free-form symbolic strings that describe what a plugin provides. By
convention they are namespaced by kind, for example:

- `pipeline:ratelimit`, `pipeline:headers`
- `provider:oidc`
- `integration:krakend`

### `depends_on` semantics

`depends_on` lists **capability names** (not plugin ids) that must be provided by *some*
registered plugin. Dependencies are resolved capability → provider when the dependency
graph is built:

- During per-manifest validation, `depends_on` entries are only checked for being present
  and non-empty.
- During `BuildDependencyGraph` (run at startup), each `depends_on` capability must be
  provided by at least one registered plugin, otherwise startup reports
  `plugin %s depends on capability %s with no providers`.
- The graph is topologically sorted (Kahn's algorithm); a cycle is reported as
  `plugin: dependency cycle`.

### `config_schema_ref`

`config_schema_ref` points at a JSON Schema under `schemas/plugins/**`. The
`FilesystemSchemaResolver` maps a ref like `pipeline/ratelimit` to
`schemas/plugins/pipeline/ratelimit.schema.json`. This is used by tooling and contract
tests (`plugin.ValidateAgainstSchema`) to validate a plugin's runtime config against its
schema; it is not consulted on the request hot path.

## Validation rules (summary)

Each manifest is validated **before** registration. Validation fails closed (the manifest
is not registered) with an error that includes the manifest path and id when:

- `id` is missing/blank,
- `kind` is missing/blank or not a known kind,
- `capabilities` is missing/empty, or contains an empty entry,
- a `depends_on` entry is empty,
- the JSON cannot be parsed.

Cross-manifest dependency resolution (unresolvable / cyclic `depends_on`) is enforced by
`BuildDependencyGraph` at startup.

## Strict mode

Two config knobs govern how discovery errors are handled at startup:

| Config key | Type | Default | Effect |
| --- | --- | --- | --- |
| `plugins_manifest_dir` | string | `""` | Directory to discover manifests. Empty disables discovery. |
| `plugins_manifest_strict` | bool | `false` | When `true`, any discovery or dependency-graph error **fails startup** (fail-closed). When `false`, errors are **logged clearly** and startup proceeds (backward-compatible best-effort behavior — errors are never silently dropped). |

Recommendation: enable `plugins_manifest_strict: true` in production so a malformed or
unresolvable manifest cannot be silently ignored.

## Signing (optional)

Manifest signing is **off by default**. When enabled, every discovered manifest must carry
a valid Ed25519 signature or discovery fails closed.

### Convention

- The manifest carries an inline `signature` object:
  `{"algorithm":"ed25519","value":"<base64>"}`.
- The signature is an **Ed25519** signature over the **canonical JSON bytes of the manifest
  with its `signature` field removed**. Canonical means: clear `signature`, then re-marshal
  the manifest with `encoding/json`; sign those exact bytes.
- `value` is **standard base64** (a raw 64-byte binary signature is also accepted).
- The public key is supplied to the proxy as a **PEM-encoded PKIX** key
  (`-----BEGIN PUBLIC KEY-----`). A bare base64 32-byte key is also accepted.

This mirrors the WASM policy-bundle signing approach documented in
[GUIDE-POLICY-SIGNING.md](./GUIDE-POLICY-SIGNING.md) and implemented in
`internal/policy/signature.go`.

### Configuration

| Config key | Type | Default | Effect |
| --- | --- | --- | --- |
| `plugins_manifest_public_key_path` | string | `""` | Path to a PEM-encoded Ed25519 public key. When set, every manifest must carry a valid signature; bad/missing signatures fail closed. An unreadable/unparseable key is always fatal, regardless of strict mode. |

### Fail-closed guarantee

When a public key is configured, the manifest is **not** registered (and, in strict mode,
startup aborts) if:

- the manifest has no `signature`,
- the `algorithm` is not `ed25519`,
- the `value` is not a valid 64-byte signature (base64 or raw),
- the signature does not verify against the configured public key (including any
  post-signing tampering of the manifest body).

## Testing checklist

- [ ] `go build ./...` and `go vet ./...` pass.
- [ ] Manifest `id` is unique across the discovery directory.
- [ ] `kind` is one of `pipeline`, `provider`, `integration`.
- [ ] `capabilities` is non-empty and each entry is meaningful/namespaced.
- [ ] Every `depends_on` capability is provided by some registered plugin (run
      `BuildDependencyGraph`; no cycles).
- [ ] If `config_schema_ref` is set, the schema exists under `schemas/plugins/**` and the
      plugin config validates against it.
- [ ] If signing is enabled, the manifest carries a valid Ed25519 signature over the
      signature-cleared canonical JSON, and verifies against the deployed public key.
- [ ] Add/extend tests: invalid/missing-field manifests, bad kind, unresolvable
      `depends_on`, and (if signed) signature pass/fail. See
      `internal/plugin/discovery_test.go`.
- [ ] Example manifests under `configs/plugins/manifests/` pass the contract test
      `test/contract` (`TestExampleManifestsAreValid`).
- [ ] Decide on `plugins_manifest_strict` per environment (recommended `true` in prod).
```
