package main

import "github.com/accessgate/accessgate/internal/policy"

// adaptPolicyEngine preserves the bootstrap seam while the proxy runtime
// now depends directly on the canonical internal policy.Engine interface.
func adaptPolicyEngine(engine policy.Engine) policy.Engine {
	return engine
}
