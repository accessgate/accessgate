# Final Repo Classification

This document is the canonical end-state classification for legacy AccessGate-adjacent repos.

The rule is simple:
- keep only the active product center and current core runtime in `accessgate/accessgate`
- create new `accessgate/*` ecosystem repos only when there is active product demand plus a real maintainer/release path
- treat predecessor repos as lineage/reference unless they still justify current extraction work

## Canonical active center

### Core
- `accessgate/accessgate`
  - classification: **core**
  - treatment: **active**
  - role: product center, core runtime, contracts, schemas, shared runtime packages, consolidation docs

## Legacy migration source

### AuthSentinel
- `ArmanAvanesyan/authsentinel`
  - classification: **archive/reference**
  - treatment: **legacy mining source only**
  - role: predecessor monorepo and architecture reference
  - note: the extraction-worthy core slices have already been rehomed into `accessgate/accessgate`
  - note: remaining residue is documented in `docs/RESIDUAL-SURFACES.md`

## PolicyFront-era split repos

### Archived lineage
- `policyfront/policyfront`
  - classification: **archive/reference**
  - treatment: legacy lineage only
- `policyfront/policyfront-docker`
  - classification: **archive/reference**
  - treatment: legacy packaging lineage only
- `policyfront/policyfront-helm-chart`
  - classification: **archive/reference**
  - treatment: legacy packaging lineage only
- `policyfront/policy-bundles`
  - classification: **archive/reference**
  - treatment: empty archived shell; do not recreate by default
- `policyfront/playground`
  - classification: **archive/reference**
  - treatment: demo lineage only
- `policyfront/plugin-caddy`
  - classification: **archive/reference**
  - treatment: integration lineage only
- `policyfront/plugin-traefik`
  - classification: **archive/reference**
  - treatment: integration lineage only
- `policyfront/plugin-krakend`
  - classification: **archive/reference**
  - treatment: integration lineage only
- `policyfront/sdk-dotnet`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-fastapi`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-flutter`
  - classification: **archive/reference**
  - treatment: empty archived shell; do not recreate by default
- `policyfront/sdk-go`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-nodejs`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-python`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-reactjs`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-typescript`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/sdk-web`
  - classification: **archive/reference**
  - treatment: SDK lineage only
- `policyfront/policyfront-observability`
  - classification: **archive/reference**
  - treatment: helper lineage only

## Ecosystem creation rule

The following areas may justify future `accessgate/*` ecosystem repos, but only when a real consumer and maintainer exist:
- SDK delivery surfaces
- gateway integrations/plugins
- packaging/deployment surfaces
- policy bundle starter examples
- observability helper packages

These are **not** current obligations. They are optional future creations, not unfinished migration debt.

## Final interpretation

After the merged consolidation slices and residual decisions:
- the active product center is `accessgate/accessgate`
- `ArmanAvanesyan/authsentinel` remains as legacy reference, not an active sibling product center
- `policyfront/*` remains archived lineage, not a second active ecosystem that must be mirrored
- no additional repo creation is required to consider the consolidation program complete
