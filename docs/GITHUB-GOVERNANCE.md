# AccessGate GitHub Governance

## Canonical ownership model
The `accessgate` organization should be the primary home for:
- product direction
- roadmap and GitHub Projects
- issue taxonomy
- architecture decisions
- canonical documentation

Legacy and transition-era surfaces should roll up into AccessGate planning even when code still lives elsewhere temporarily.

## Recommended organization projects

### 1. AccessGate Consolidation
Purpose:
- absorb useful work from `authsentinel`
- map and govern `policyfront` ecosystem repos
- track renames, migrations, archive work, and ownership cleanup

Suggested statuses:
- Inbox
- Triaged
- Ready
- In Progress
- In Review
- Blocked
- Done
- Archived

Suggested custom fields:
- Area: Core Runtime, Auth, Proxy, Policy, SDK, Plugin, Docs, Packaging, Observability, Migration
- Source: AccessGate, AuthSentinel, PolicyFront
- Track: Core, Ecosystem, Legacy, Docs, Governance
- Priority: P0, P1, P2, P3

### 2. AccessGate Core Roadmap
Purpose:
- active product development for the core runtime
- features, bugs, ADRs, release readiness

Suggested statuses:
- Backlog
- Ready
- In Progress
- In Review
- Release Ready
- Done

Suggested custom fields:
- Area: Core Runtime, Auth, Proxy, Policy, Config, Test
- Priority: P0, P1, P2, P3
- Release: Now, Next, Later

### 3. AccessGate Docs & Developer Experience
Purpose:
- documentation quality
- onboarding
- examples
- migration guides
- SDK and plugin docs consistency

Suggested statuses:
- Inbox
- Ready
- In Progress
- In Review
- Published

Suggested custom fields:
- Audience: User, Operator, Contributor, SDK Consumer
- Area: Product, Architecture, Migration, SDK, Plugin, Operations

## Labels
Source of truth for labels:
- `.github/labels.yml`

Label groups:
- Area labels
- Source lineage labels
- Work type labels
- Status labels
- Priority labels

## Issue templates
Source of truth:
- `.github/ISSUE_TEMPLATE/`

Starter templates:
- Core feature
- Ecosystem task
- Legacy migration
- Documentation gap

## Pull requests
Use a simple PR template requiring:
- summary
- scope
- testing/verification
- migration impact
- docs impact

## Rollout order
1. Create labels from `.github/labels.yml`
2. Enable issue templates
3. Create the three GitHub Projects above
4. Seed `AccessGate Consolidation` first
5. Move active current-product work into `AccessGate Core Roadmap`
