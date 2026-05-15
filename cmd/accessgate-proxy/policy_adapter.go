package main

import "github.com/ArmanAvanesyan/accessgate/internal/policy"

// adaptPolicyEngine preserves the bootstrap seam while the proxy runtime
// now depends directly on the canonical internal policy.Engine interface.
func adaptPolicyEngine(engine policy.Engine) policy.Engine {
	return engine
}
