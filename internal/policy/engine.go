package policy

import "context"

// Engine evaluates authorization decisions using embedded policy bundles.
type Engine interface {
	Evaluate(ctx context.Context, input Input) (*Decision, error)
}

// EngineWithStatus is optional: engines that report bundle load status for admin/observability.
type EngineWithStatus interface {
	Engine
	Loaded() bool
	BundlePath() string
}
