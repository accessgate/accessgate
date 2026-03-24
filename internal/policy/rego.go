package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
)

// RegoEngine runs policies written in Rego (OPA-style) embedded in the proxy.
//
// Contract:
//   - The policy must define `package accessgate`.
//   - The query evaluated is `data.accessgate.decision`.
//   - The result value must be an object with shape compatible with Decision:
//     { "allow": bool, "status_code": number, "reason": string, "headers": {string:string}, "obligations": object }.
type RegoEngine struct {
	mu       sync.RWMutex
	fallback FallbackConfig

	bundlePath string
	prepared   *rego.PreparedEvalQuery
}

func NewRegoEngine(fallback FallbackConfig) *RegoEngine {
	return &RegoEngine{fallback: fallback}
}

// Load loads and compiles a Rego module from the given file path.
func (r *RegoEngine) Load(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy: read rego: %w", err)
	}

	ctx := context.Background()
	q, err := rego.New(
		rego.Query("data.accessgate.decision"),
		rego.Module("accessgate.rego", string(src)),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("policy: compile rego: %w", err)
	}

	r.mu.Lock()
	r.bundlePath = path
	r.prepared = &q
	r.mu.Unlock()
	return nil
}

func (r *RegoEngine) Evaluate(ctx context.Context, input Input) (*Decision, error) {
	r.mu.RLock()
	prepared := r.prepared
	r.mu.RUnlock()

	if prepared == nil {
		return r.fallbackDecision(), nil
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return r.fallbackDecision(), nil
	}

	decision, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return r.fallbackDecision(), nil
	}

	return decisionFromAny(decision, r.fallbackDecision()), nil
}

func (r *RegoEngine) fallbackDecision() *Decision {
	if r.fallback.Allow {
		return &Decision{Allow: true, StatusCode: 200}
	}
	return &Decision{Allow: false, StatusCode: 503, Reason: "policy unavailable"}
}

func (r *RegoEngine) Loaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.prepared != nil
}

func (r *RegoEngine) BundlePath() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bundlePath
}

func decisionFromAny(m map[string]any, fallback *Decision) *Decision {
	out := *fallback

	if v, ok := m["allow"].(bool); ok {
		out.Allow = v
	}
	if v, ok := asInt(m["status_code"]); ok {
		out.StatusCode = v
	}
	if v, ok := m["reason"].(string); ok {
		out.Reason = v
	}
	if raw, ok := m["headers"].(map[string]any); ok {
		if out.Headers == nil {
			out.Headers = make(map[string]string, len(raw))
		}
		for k, rv := range raw {
			if s, ok := rv.(string); ok {
				out.Headers[k] = s
			}
		}
	}
	if raw, ok := m["obligations"].(map[string]any); ok {
		out.Obligations = raw
	}

	return &out
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case float32:
		return int(t), true
	case float64:
		return int(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case string:
		n := json.Number(t)
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}
