# AccessGate v1.0 Compatibility & Stability Contract

> Status: proposed for the `v1.0` milestone (umbrella [#86](https://github.com/accessgate/accessgate/issues/86)).
> Scope: the **accessgate core** module `github.com/accessgate/accessgate`.

This document is the stability contract for AccessGate v1.0. It defines what we
promise not to break within the v1.x line, how that promise is mechanically
enforced, and the deprecation path for evolving each surface. It covers three
surfaces:

1. **Config schema** — `schemas/{auth,proxy}.schema.json`
2. **Proto contract** — `proto/accessgate/{auth,policy,proxy,sdk}/v1/*.proto`
3. **Public Go API** — the exported surface under `pkg/**`

Everything under `internal/**` is explicitly **not** part of the contract and may
change at any time.

---

## 1. Config schema freeze

### The contract

The committed JSON Schemas are the stable config contract:

- `schemas/auth.schema.json` — for `accessgate-auth`
- `schemas/proxy.schema.json` — for `accessgate-proxy`

They are **generated**, not hand-written: `make schema` runs `cmd/schema`, which
reflects the config structs (`internal/auth/config/config.go`,
`internal/proxy/config/config.go`) into JSON Schema. Human-readable docs for
every key live in [`docs/CONFIG-KEYS.md`](./CONFIG-KEYS.md).

### Shape: closed, fully-enumerated objects

The generator (`cmd/schema/main.go`, `boundSchemaValue`) sets
`additionalProperties: false` on every object node, and the struct reflection
lists every field in the `required` array. The result is a **closed schema with
all keys required** (verify: `schemas/auth.schema.json` lists all 28 auth keys in
`required`; the root and the nested `pipeline_plugins` entries in
`schemas/proxy.schema.json` are likewise `additionalProperties: false`).

Practically this means:

- An **unknown key is an error** (typos, removed keys, or keys from a future
  version fail validation against an older binary's schema).
- The schema documents the **full** key set; "required" here means "known to the
  schema," not "operator must supply a value" — runtime requiredness and
  defaulting are enforced separately by each config's `Validate()` /
  `ApplyDefaults()` (see `docs/CONFIG-KEYS.md`).

This closed shape is the thing we freeze for v1.0: the set of recognized keys and
their types is the contract.

### Regen discipline (drift enforcement)

The schema is mechanically prevented from drifting away from the structs. CI
(`.github/workflows/ci.yaml`, step **"Verify config schemas are up to date"**)
runs `make schema` and then `git diff --exit-code schemas/`. Any change to a
config struct that is not accompanied by a regenerated, committed schema fails
the build. A second step, **"Validate example configs"**, validates the shipped
`configs/{auth,proxy}.example.{json,yaml}` against both the generated schema and
the runtime `Load+Validate` rules.

Discipline for contributors: **never hand-edit `schemas/*.json`**. Change the
struct, run `make schema`, commit both.

### Deprecation policy for config keys

Within v1.x, evolve config keys as follows:

- **Add a key:** additive and backward-compatible. New keys must be optional at
  runtime (have an `ApplyDefaults()` default or be genuinely optional in
  `Validate()`), so existing configs keep working. Regenerate the schema.
- **Rename a key:** keep the old name as a recognized alias for the whole v1.x
  line; have the loader accept both, prefer the new name, and emit a deprecation
  warning when the old one is used. The established precedent is the
  `AGENT_CONFIG` → `AUTH_CONFIG` env alias (and the `BINARY=agent` →
  `BINARY=auth` alias in `cmd/validateconfig/main.go:25-67`), documented in
  `docs/CONFIG-KEYS.md`. Removal of a deprecated alias waits for v2.0.
- **Remove a key:** deprecate first (document it, warn at load), then remove only
  in a major version. Removing a recognized key in v1.x would turn previously
  valid configs into validation errors (closed schema), so it is a breaking
  change.

### Keys to reconsider before freezing for 1.0

These are recommendations, not blockers — see the checklist at the end.

- **`allow_private_upstreams` (proxy):** an SSRF-bypass foot-gun. The name and
  docs are clear ("Never enable in production"), but once frozen the key name is
  permanent. Confirm we are happy with the name/semantics now.
- **`grpc_upstream_insecure` (proxy):** plaintext-transport toggle in the same
  foot-gun category. Same reasoning — lock the name deliberately.
- **`policy_fallback_allow` (proxy):** documented as "bool (nullable)" in
  `docs/CONFIG-KEYS.md`. Nullable-bool config keys are awkward to express in a
  closed JSON Schema and to reason about for operators. Confirm the schema's
  generated type for this key matches intent before freeze.
- **`cookie_same_site` runtime field:** the parsed `http.SameSite` value carries
  `json:"-"` and is correctly *not* a config key. Good as-is — just confirm the
  generated schema does not leak it.
- **`AGENT_CONFIG` / `BINARY=agent`:** already deprecated aliases. They are fine
  to carry through v1.x; just record them explicitly as "deprecated, removal in
  v2.0" so the removal is not a surprise.

---

## 2. Proto contract stability

### The contract

The v1 protobuf packages are stable wire/API contracts:

- `accessgate.auth.v1` — `proto/accessgate/auth/v1/auth.proto` (`AuthService`:
  Login, Callback, Refresh, Logout, IntrospectSession)
- `accessgate.policy.v1` — `proto/accessgate/policy/v1/policy.proto`
  (`PolicyService.Evaluate`)
- `accessgate.proxy.v1` — `proto/accessgate/proxy/v1/proxy.proto`
  (`ProxyService`: Decide, IntrospectPrincipal, ResolveRoute)
- `accessgate.sdk.v1` — `proto/accessgate/sdk/v1/identity.proto` (`Principal`,
  `Session`, `AuthContext`)

### Enforcement: the buf breaking gate

`proto/buf.yaml` configures lint (`STANDARD`) and breaking detection at the
`FILE` level, with one exception: `FILE_SAME_GO_PACKAGE` (excluded so the
one-time `ArmanAvanesyan/accessgate` → `accessgate/accessgate` Go-package rename
is not flagged — it affects only the generated Go import path, not the wire
format). CI (`.github/workflows/ci.yaml`) runs `make proto-lint` on every build
and `make proto-breaking` (`buf breaking --against .git#branch=main`) on every
pull request, plus regenerates code and runs `git diff --exit-code proto/gen/` to
ensure committed bindings match the protos.

Net effect: **any wire-breaking change to a v1 proto fails CI.** Field
renumbering, type changes, removals, and other `FILE`-level breaks are rejected.
This is the mechanical guarantee behind v1 proto stability.

### `accessgate.sdk.v1` — the SDK source of truth

`accessgate.sdk.v1` is special: it is the single canonical SDK contract, per
[`docs/SDK-REGISTRY.md`](./SDK-REGISTRY.md). Every SDK — current or future —
implements this proto. Language bindings are generated under `proto/gen/{go,ts}`,
and the shape is pinned by the contract test
`test/contract/sdk_agent_contract_test.go`. The governance rules there already
codify the right policy: additive optional fields stay in v1; any
semantics-changing or field-removing change requires a new `accessgate.sdk.v2`
package rather than mutating v1, coordinated across all conforming SDKs. v1.0
adopts that policy verbatim as the SDK stability promise.

### Proto cleanups to consider before 1.0

- No `deprecated`, `reserved`, `TODO`, or `FIXME` markers exist in any v1 proto
  (verified). The surface is clean.
- **Reserve renumbering headroom:** before freeze, sanity-check that message
  field numbers reflect the intended long-term shape. Once v1 is frozen, the only
  forward path is additive (new field numbers). This is a one-time "are we happy
  with the numbering?" review, not a change request.
- **`FILE_SAME_GO_PACKAGE` exception:** the module rename is long done. Consider
  whether this exception can be dropped post-1.0 to tighten the gate (low
  priority; harmless if left).

---

## 3. Public Go API (`pkg/**`) stability tiers

The exported Go surface is ~35 non-test files across
`pkg/{auth,cookie,observability,oidc,sdk,session,token}`. AccessGate core is
imported as a library (the `pkg/sdk` helpers and identity types are designed for
server-side integration), so `pkg/**` carries a SemVer commitment.

### Stability tiers

| Tier | Packages | Commitment in v1.x |
| --- | --- | --- |
| **Stable** | `pkg/sdk`, `pkg/token`, `pkg/session`, `pkg/cookie`, `pkg/oidc`, `pkg/auth` | No breaking changes within v1. Additive only (new functions, new optional fields, new methods on our own interface impls — not on exported *interfaces*). |
| **Stable (interface-shaped)** | `pkg/observability` | Interfaces (`Logger`, `Metrics`, `Tracer`, `Span`, `Provider`) are stable; adding methods to these interfaces is breaking and deferred to v2. New constructors/impls are additive. |

There is no `pkg/**internal` or unexported-by-convention sub-tier today; the
"Internal-ish" classification below flags specific exported symbols that should
move *before* freeze rather than a whole tier.

### SemVer commitment for v1.x

Within the v1 major line:

- **No breaking change** to any Stable exported symbol: no removing/renaming
  exported types, funcs, methods, or struct fields; no changing function
  signatures; no adding methods to exported *interfaces* (that breaks external
  implementers — `Logger`, `Metrics`, `Tracer`, `Span`, the `cookie.Codec` /
  `cookie.Manager` interfaces, the `session.*Store` interfaces, `auth.Service`,
  `token.Validator`, `token.JWKSSource`).
- **Allowed:** new packages, new exported functions/types, new struct fields on
  request/response DTOs (additive), new constructors.
- Breaking changes wait for v2.0.

### Exported symbols to review before freeze (Internal-ish / accidental)

These look like surface that may have been exported incidentally. Each is a
candidate to **unexport or move to `internal/`** before v1.0, because doing so
after freeze would be a breaking change:

- **`token.NopMetrics` and `observability.NopMetrics` / `NopLogger` /
  `NopTracer`:** nop implementations are genuinely useful to external callers
  (testing seams), so these are probably *intended* Stable surface — but confirm
  that intent. If they exist only for internal tests, unexport them now.
- **`token.Metrics` (in `pkg/token/jwks.go`) vs `observability.Metrics`:** two
  separate exported `Metrics` interfaces. Confirm `pkg/token` genuinely needs its
  own metrics interface rather than depending on `observability.Metrics`; a
  duplicate exported interface is easy to freeze by accident.
- **`cookie` package breadth:** it exports `Codec`, `RotatingCodec`, `Manager`,
  `SignedManager`, `SignedCodec`, `CookieOptions`, `OutCookie`,
  `SessionCookieConfig`, plus free functions `EncodeValue`/`DecodeValue`/
  `Encrypt`/`Decrypt`/`ReadSessionID`/`WriteOutCookie`. Some of these (raw
  `Encrypt`/`Decrypt` over `[]byte`) read like low-level primitives that callers
  should not depend on. Decide which are public API vs internal crypto helpers
  before freeze.
- **`session` store interfaces:** `SessionStore`, `PKCEStore`,
  `RefreshLockStore`, `RevocationStore`, `ReplayStore`, `RuntimeStoreProvider`,
  `ExtendedRuntimeStoreProvider`. The split between `RuntimeStoreProvider` and
  `ExtendedRuntimeStoreProvider` suggests an interface that was extended
  additively to avoid a break — confirm this is the intended long-term shape, as
  it freezes at v1.

### No Go API-diff gate today — recommended follow-up

Proto has `buf breaking`; config has the `make schema` drift check. **Go has no
equivalent automated API-diff gate.** Nothing today prevents an accidental
breaking change to `pkg/**`.

**Recommendation (file as a follow-up under #86, do not implement here):** add a
CI job that runs `golang.org/x/exp/cmd/apidiff` (or `gorelease`) against the last
release tag for the `pkg/**` packages and fails on incompatible changes — the Go
analogue of the buf breaking gate. This closes the one surface that is currently
guarded by review discipline alone.

---

## Pre-1.0 cleanup checklist

Concrete, optional-but-recommended items to resolve before tagging v1.0. None are
code changes mandated by this doc; they are decisions to lock deliberately.

- [ ] **Config:** confirm final names/semantics for the foot-gun keys
  `allow_private_upstreams`, `grpc_upstream_insecure`, and the nullable-bool
  `policy_fallback_allow`; once frozen, names are permanent.
- [ ] **Config:** record `AGENT_CONFIG` / `BINARY=agent` explicitly as
  "deprecated, removal in v2.0" (already aliased; just make the lifecycle
  explicit).
- [ ] **Proto:** one-time review of v1 message field numbering for long-term
  additive headroom; confirm no message needs a pre-freeze restructure.
- [ ] **Go API:** decide the fate of incidentally-exported symbols —
  `token.Metrics` vs `observability.Metrics` duplication, the low-level
  `cookie.Encrypt`/`Decrypt` primitives, and whether the various `Nop*` impls are
  intended public surface. Unexport/move anything that should be internal *now*.
- [ ] **Go API:** confirm the `session.RuntimeStoreProvider` /
  `ExtendedRuntimeStoreProvider` split is the intended frozen shape.
- [ ] **Tooling (follow-up issue under #86):** add an `apidiff`/`gorelease` CI
  gate for `pkg/**` to mechanically enforce the Go SemVer promise — parity with
  the existing `buf breaking` and `make schema` gates.

## What v1.0 guarantees

- **Config:** the recognized key set and types for `accessgate-auth` and
  `accessgate-proxy` are frozen. The schemas are closed
  (`additionalProperties:false`) and generated from the structs; CI prevents
  drift. New keys may be added (optional, with defaults); existing keys are not
  removed or retyped within v1.x. Renames go through a deprecation-aliased path
  (the `AGENT_CONFIG` → `AUTH_CONFIG` precedent).
- **Proto:** the `accessgate.{auth,policy,proxy,sdk}.v1` packages are stable wire
  contracts. `buf breaking` in CI rejects any wire-breaking change. Breaking the
  SDK contract requires `accessgate.sdk.v2`, never a mutation of v1.
- **Go API:** the Stable-tier `pkg/**` packages carry a SemVer promise — no
  breaking changes within v1.x, additive evolution only. `internal/**` is
  excluded from all guarantees and may change freely.
