# AccessGate Lineage

## Canonical identity
AccessGate is the current canonical product identity and core runtime.

## Lineage
1. **AuthSentinel** - early integrated monorepo/runtime phase
2. **PolicyFront** - split ecosystem phase (SDKs, plugins, bundles, packaging, playground)
3. **AccessGate** - current core runtime identity and future product center

## Current interpretation
- `accessgate/accessgate` = canonical core runtime
- `accessgate/authsentinel` = **canonical legacy home** (archived, read-only) for the AuthSentinel ancestor
- `policyfront/*` = externalized ecosystem repos from the earlier naming phase (all archived, read-only)

## Repository status (reconciled 2026-06-05)
- `accessgate/authsentinel` — **archived**, designated canonical legacy ancestor.
- `ArmanAvanesyan/authsentinel` — **archived duplicate** of the above; do not use.
- `policyfront/*` (18 repos) — **archived**; frozen ecosystem history.
- Full reconciliation: [`audit/AUDIT-2026-06-05.md`](audit/AUDIT-2026-06-05.md).

## Practical rule
When there is naming or ownership ambiguity:
- prefer **AccessGate** for current docs, roadmap, and product decisions
- treat **AuthSentinel** as historical context
- treat **PolicyFront** repos as ecosystem components, not the canonical center