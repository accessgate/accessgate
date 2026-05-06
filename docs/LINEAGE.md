# AccessGate Lineage

## Canonical identity
AccessGate is the current canonical product identity and core runtime.

## Lineage
1. **AuthSentinel** - early integrated monorepo/runtime phase
2. **PolicyFront** - split ecosystem phase (SDKs, plugins, bundles, packaging, playground)
3. **AccessGate** - current core runtime identity and future product center

## Current interpretation
- `accessgate/accessgate` = canonical core runtime
- `ArmanAvanesyan/authsentinel` = legacy predecessor monorepo
- `policyfront/*` = externalized ecosystem repos from the earlier naming phase

## Practical rule
When there is naming or ownership ambiguity:
- prefer **AccessGate** for current docs, roadmap, and product decisions
- treat **AuthSentinel** as historical context
- treat **PolicyFront** repos as ecosystem components, not the canonical center