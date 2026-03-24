# Protobuf APIs

Buf configuration lives at the repository root (`buf.gen.yaml`, `buf.work.yaml`). Generate code with `make proto-generate`.

Packages under `proto/accessgate/`:

- `accessgate/auth/v1`: Auth login, callback, refresh, logout, and session introspection (`AuthService`).
- `accessgate/proxy/v1`: Request decision, principal introspection, route resolution, and deny reason model.
- `accessgate/policy/v1`: Policy evaluation request/response, obligations, and trace/debug structures.
- `accessgate/sdk/v1`: Shared principal, session, and auth context messages used by SDKs.
