# AccessGate Repo Map

## Core
- `accessgate/accessgate`
  - current runtime core
  - auth runtime
  - proxy runtime
  - contracts/schemas
  - shared runtime packages

## Legacy
- `ArmanAvanesyan/authsentinel`
  - legacy monorepo predecessor
  - source of migration ideas, old architecture context, and backlog mining

## Ecosystem (PolicyFront-era split repos)
- `policyfront/policyfront`
- `policyfront/policyfront-docker`
- `policyfront/policyfront-helm-chart`
- `policyfront/policy-bundles`
- `policyfront/playground`
- `policyfront/plugin-caddy`
- `policyfront/plugin-traefik`
- `policyfront/plugin-krakend`
- `policyfront/sdk-dotnet`
- `policyfront/sdk-fastapi`
- `policyfront/sdk-flutter`
- `policyfront/sdk-go`
- `policyfront/sdk-nodejs`
- `policyfront/sdk-python`
- `policyfront/sdk-reactjs`
- `policyfront/sdk-typescript`
- `policyfront/sdk-web`
- `policyfront/policyfront-observability`

## Ownership model
- **Core decisions** live in `accessgate/accessgate`
- **Ecosystem repo decisions** should still roll up into AccessGate planning
- **Legacy mining** comes from `authsentinel`
