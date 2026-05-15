# Residual Ecosystem Surfaces

This note captures the final interpretation of the remaining AuthSentinel residue after the first AccessGate consolidation wave.

## Closed core work
- Runtime, store, schema/validation, Go SDK helper, and shared plugin-platform seams were already rehomed into `accessgate/accessgate`.
- That work closed the code-bearing slices previously tracked by `#13`, `#14`, `#23`, `#24`, and `#25`.

## Policy bundle surface
Source reviewed:
- `ArmanAvanesyan/authsentinel/packages/policy-bundles/**`
- `policyfront/policy-bundles`

What remains:
- small example bundles (`allow_all.rego`, `deny_all.rego`)
- minimal README scaffolding for `core`, `graphql`, and `grpc`
- no substantial packaging, publishing, or maintained delivery workflow
- archived PolicyFront split repo is empty

Decision:
- keep the policy engine, config contract, and bundle-loading runtime in core
- treat the current AuthSentinel policy-bundle package as example/demo lineage, not a migration-worthy standalone repo
- recreate example bundles later only if operator docs or starter kits need them

Result:
- no dedicated extraction repo is needed now
- this surface is resolved as docs/example-only residue

## Flutter SDK surface
Source reviewed:
- `ArmanAvanesyan/authsentinel/packages/sdk/flutter/sdk_flutter/**`
- `policyfront/sdk-flutter`

What remains:
- a small client package around agent login/session endpoints
- widget glue (`AuthScope`) and a toy example app
- generated/tool residue (`.dart_tool`, lockfiles, Flutter plugin metadata)
- package version `0.0.0`
- archived PolicyFront split repo is empty

Decision:
- preserve the API shape and client intent as ecosystem lineage
- do not rehome the current Flutter package into core
- do not create a dedicated AccessGate Flutter repo until there is active product demand, a stable client contract, and an actual release owner

Result:
- this surface is resolved as deferred ecosystem potential, not current migration work
- preserve it as reference only; reopen as a new ecosystem delivery task when there is a real consumer

## Mining completion
After these decisions:
- no additional AuthSentinel surfaces currently justify new AccessGate extraction issues
- remaining residue is lineage, docs, demo, or harness material unless new product demand appears
