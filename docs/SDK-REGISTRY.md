# AccessGate SDK Registry

> Source-of-truth registry for AccessGate SDKs and integration plugins.

## Canonical contract

The single canonical SDK contract for AccessGate is the protobuf package
**`accessgate.sdk.v1`**, defined in
[`proto/accessgate/sdk/v1/identity.proto`](../proto/accessgate/sdk/v1/identity.proto).

Every SDK — current or future — implements this contract. The proto defines the
normalized identity model shared across `accessgate-auth`, `accessgate-proxy`,
AccessGate Policy, and all client SDKs:

- `Principal` — normalized subject, scopes, roles, claims, tenant context, token, expiry.
- `Session` — persisted auth session (access/refresh/ID tokens, claims, tenant context).
- `AuthContext` — the wrapper passed between components and exposed to SDKs.

Language bindings are generated from this proto into:

- Go: [`proto/gen/go/accessgate/sdk/v1`](../proto/gen/go)
- TypeScript: [`proto/gen/ts/accessgate/sdk`](../proto/gen/ts)

The protocol shape is enforced by the contract test
[`test/contract/sdk_agent_contract_test.go`](../test/contract/sdk_agent_contract_test.go).

The proto contract is the durable anchor: SDK implementations may be archived,
recreated, or deferred, but the contract they must satisfy lives here in core.

## Registry

Status legend:

- **active** — code-bearing implementation that reflects the SDK surface (currently
  preserved as archived historical lineage; see Lineage note below).
- **partial** — code present but incomplete or early-stage.
- **empty-shell** — repository exists but contains no real content; candidate for
  archival/removal.
- **archived** — PolicyFront-era repository, frozen and read-only on GitHub. This is a
  lineage/governance status that applies on top of the content status.

All PolicyFront-era SDK and plugin repositories are **archived** (read-only) per
[`docs/LINEAGE.md`](./LINEAGE.md) and [`docs/REPO-MAP.md`](./REPO-MAP.md). The
content column below records what each archived repo actually contains, based on a
verified file inventory of `repos/policyfront/*`.

### SDKs

| SDK | Language | Content status | Repo status | Notes |
| --- | --- | --- | --- | --- |
| `sdk-go` | Go | active | archived | Real content (8 files). Go SDK helper seams were already rehomed into `accessgate/accessgate` core. |
| `sdk-nodejs` | JavaScript (Node) | active | archived | Real content (27 files). PolicyFront-era client SDK. |
| `sdk-typescript` | TypeScript | active | archived | Real content (27 files). PolicyFront-era client SDK. |
| `sdk-reactjs` | TypeScript/React | active | archived | Real content (25 files). React bindings over the client SDK. |
| `sdk-web` | TypeScript/Web | active | archived | Real content (30 files). Browser/web client SDK. |
| `sdk-flutter` | Dart/Flutter | active | archived | Real content (18 files). Small client + `AuthScope` widget glue; preserved as deferred ecosystem lineage per [RESIDUAL-SURFACES.md](./RESIDUAL-SURFACES.md). |
| `sdk-dotnet` | C#/.NET | empty-shell | archived | No real content (0 files). Candidate for archival/removal. |
| `sdk-fastapi` | Python (FastAPI) | empty-shell | archived | No real content (0 files). Candidate for archival/removal. |
| `sdk-python` | Python | empty-shell | archived | No real content (0 files). Candidate for archival/removal. |

### Plugins

| Plugin | Target | Content status | Repo status | Notes |
| --- | --- | --- | --- | --- |
| `plugin-caddy` | Caddy | active | archived | Real content (7 files). PolicyFront-era integration plugin. |
| `plugin-traefik` | Traefik | active | archived | Real content (5 files). PolicyFront-era integration plugin. |
| `plugin-krakend` | KrakenD | active | archived | Real content (5 files). PolicyFront-era integration plugin. |

### Current reality

- There is **no** maintained, published SDK distribution home today. The
  PolicyFront-era repos are archived historical lineage, not active product centers
  (see [`docs/REPO-MAP.md`](./REPO-MAP.md)).
- The durable, maintained artifact is the `accessgate.sdk.v1` proto contract and its
  generated bindings inside `accessgate/accessgate`.
- The three empty shells — `sdk-dotnet`, `sdk-fastapi`, `sdk-python` — carry no
  content and are candidates for archival/removal. They do not justify one-for-one
  recreation under `accessgate` (per the Repo Map's current interpretation).

## Governance

1. **Proto version tracking.** Every SDK (current archived implementations and any
   future maintained SDK) must track the `accessgate.sdk.v1` contract version it
   implements. The proto package version is the source of truth; SDK releases declare
   which proto version they conform to.

2. **Breaking changes require coordination.** Changes to
   [`proto/accessgate/sdk/v1/identity.proto`](../proto/accessgate/sdk/v1/identity.proto)
   that alter the contract (removing/renumbering fields, changing semantics) are
   breaking changes. They require:
   - a new proto package version (e.g. `accessgate.sdk.v2`) rather than mutating v1,
   - regeneration of bindings under `proto/gen/`,
   - an update to the contract test
     [`test/contract/sdk_agent_contract_test.go`](../test/contract/sdk_agent_contract_test.go),
     and
   - coordinated updates across every SDK that claims conformance.
   Additive, backward-compatible changes (new optional fields with new field numbers)
   may stay within v1.

3. **Where future maintained SDKs should live.** New ecosystem/SDK repos should be
   created **only** for surfaces with clear current product demand and a maintained
   packaging/publishing path, with a named release owner (per
   [`docs/REPO-MAP.md`](./REPO-MAP.md)). Until then:
   - the proto contract and generated bindings in `accessgate/accessgate` remain the
     authoritative SDK surface, and
   - archived PolicyFront repos remain reference-only lineage and must not be treated
     as the maintained home.
   - Deferred surfaces (e.g. Flutter) are reopened as new ecosystem delivery tasks only
     when there is a real consumer, a stable client contract, and a release owner
     (per [`docs/RESIDUAL-SURFACES.md`](./RESIDUAL-SURFACES.md)).

## See also

- [`docs/REPO-MAP.md`](./REPO-MAP.md)
- [`docs/LINEAGE.md`](./LINEAGE.md)
- [`docs/RESIDUAL-SURFACES.md`](./RESIDUAL-SURFACES.md)
