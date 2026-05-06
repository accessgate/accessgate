# AccessGate Consolidation

## Goal
Make **AccessGate** the single active product center for:
- docs
- roadmap
- GitHub Projects
- backlog
- architectural decisions

## Proposed GitHub Project
**Name:** `AccessGate Consolidation`

### Suggested fields
- **Status**
  - Inbox
  - Triaged
  - Keep in Core
  - Split to Ecosystem
  - Docs Needed
  - Migration Needed
  - Legacy / Archive
  - Done
- **Area**
  - Core Runtime
  - Auth
  - Proxy
  - Policy
  - SDK
  - Plugin
  - Docs
  - Packaging
  - Observability
  - Migration
- **Source**
  - AccessGate
  - AuthSentinel
  - PolicyFront Org
- **Priority**
  - P0
  - P1
  - P2
  - P3

## Suggested issue types
- `feature/core`
- `feature/sdk`
- `feature/plugin`
- `migration/task`
- `migration/legacy-audit`
- `docs/architecture`
- `docs/product`
- `docs/migration`
- `archive/legacy`
- `decision/adr`

## Backlog conversion rules
### Keep in Core
Use for:
- runtime behavior
- core auth/proxy capabilities
- contracts, schemas, shared packages

### Split to Ecosystem
Use for:
- SDKs
- gateway plugins
- docker/helm packaging
- playground/demo assets
- observability helpers

### Legacy / Archive
Use for:
- superseded monorepo-only structure
- stale experiments
- duplicate implementations
- old naming leftovers

## First recommended backlog epics
1. Canonicalize AccessGate naming everywhere
2. Mine AuthSentinel for migration tasks
3. Map PolicyFront repos to AccessGate ownership model
4. Define core vs ecosystem repo boudaries
5. Archive or freeze legacy surfaces safely
