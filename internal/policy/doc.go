// Package policy provides the authorization policy engine for AccessGate (accessgate-proxy / AccessGate Policy).
//
// It handles:
//   - Authorization rules: evaluation of allow/deny decisions from request context
//     (protocol, method, path, principal, headers) via the Engine interface and
//     Input/Decision types.
//   - Rego/WASM execution: policy bundles can be expressed as Rego (e.g. OPA-style)
//     or compiled to WASM; the engine runs them to produce Decisions.
//
// Implementations (WASMRuntime, RegoEvaluator, or combined) satisfy Engine
// and are responsible for loading and executing the actual rules.
package policy
