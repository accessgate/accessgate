package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	"github.com/accessgate/accessgate/internal/policy"
	"github.com/accessgate/accessgate/pkg/observability"
	"github.com/accessgate/accessgate/pkg/token"
)

// PrincipalResolver resolves the principal (identity) from a proxy request (e.g. via session cookie or JWT).
type PrincipalResolver interface {
	Resolve(ctx context.Context, req *Request) (*token.Principal, error)
}

// HeaderBuilder builds upstream headers from principal and policy obligations.
// If nil, DefaultEngine uses a default that sets X-User-Id, X-Roles, and obligation-derived headers.
type HeaderBuilder func(principal *token.Principal, obligations map[string]any) map[string]string

// PipelinePlugin is the minimal interface needed by the proxy engine to run
// optional pipeline steps.
//
// We keep this interface local to pkg/proxy to avoid an import cycle with
// pkg/pluginapi (which itself references pkg/proxy types).
type PipelinePlugin interface {
	Handle(ctx context.Context, req *Request, principal *token.Principal) (*policy.Decision, error)
}

// DefaultEngine implements Engine: normalizes request, resolves principal, evaluates policy, maps decision to response.
type DefaultEngine struct {
	Resolver PrincipalResolver
	Policy   policy.Engine
	// PipelinePlugins is an optional list of pipeline plugins that can participate
	// in the request flow. If any plugin returns a non-nil Decision, the engine
	// short-circuits and uses that Decision instead of calling Policy.
	PipelinePlugins []PipelinePlugin
	UpstreamURL     string
	RequireAuth     bool
	HeaderBuilder   HeaderBuilder
	// UnauthenticatedMode controls the unauthenticated response: "" / "api_401" returns a JSON
	// 401 (default); "html_redirect" returns a denied response with RedirectTo set to
	// LoginRedirectURL so the HTTP layer issues a 302.
	UnauthenticatedMode string
	LoginRedirectURL    string
	Metrics             observability.Metrics // optional; records auth decisions
	Tracer              observability.Tracer  // optional; records best-effort spans
}

// Handle implements Engine.Handle.
func (e *DefaultEngine) Handle(ctx context.Context, req *Request) (*Response, error) {
	tr := e.Tracer
	if tr == nil {
		tr = observability.NopTracer{}
	}
	ctx, rootSpan := tr.StartSpan(ctx, "proxy.handle", "method", req.Method, "path", req.Path, "require_auth", e.RequireAuth)
	defer rootSpan.End()

	// Principal resolution: session/JWT -> principal.
	_, principalSpan := tr.StartSpan(ctx, "proxy.principal_resolve")
	principal, err := e.Resolver.Resolve(ctx, req)
	principalSpan.End()
	if err != nil {
		return &Response{
			Allow:      false,
			StatusCode: http.StatusBadGateway,
			Body:       []byte(`{"errors":[{"message":"auth resolution failed"}]}`),
		}, nil
	}
	if principal == nil && e.RequireAuth {
		if e.UnauthenticatedMode == "html_redirect" && e.LoginRedirectURL != "" {
			if e.Metrics != nil {
				e.Metrics.AuthDecision(false, http.StatusFound)
			}
			return &Response{
				Allow:      false,
				StatusCode: http.StatusFound,
				RedirectTo: e.LoginRedirectURL,
			}, nil
		}
		return &Response{
			Allow:      false,
			StatusCode: http.StatusUnauthorized,
			Body:       []byte(`{"errors":[{"message":"unauthorized"}]}`),
		}, nil
	}

	// Optional pipeline plugins run before the main policy engine.
	// If a plugin returns a decision, we short-circuit policy evaluation and use it.
	var decision *policy.Decision
	for i, p := range e.PipelinePlugins {
		if p == nil {
			continue
		}
		pluginType := reflect.TypeOf(p).String()
		_, pSpan := tr.StartSpan(ctx, "proxy.pipeline_plugin", "plugin_index", i, "plugin_type", pluginType)
		pd, err := p.Handle(ctx, req, principal)
		pSpan.End()
		if err != nil {
			return &Response{
				Allow:      false,
				StatusCode: http.StatusServiceUnavailable,
				Body:       []byte(`{"errors":[{"message":"pipeline plugin error"}]}`),
			}, nil
		}
		if pd != nil {
			decision = pd
			break
		}
	}

	// Main policy evaluation if no plugin decision was produced.
	if decision == nil {
		_, policySpan := tr.StartSpan(ctx, "proxy.policy_evaluate")
		input := policy.Input{
			Protocol:         req.Protocol,
			Method:           req.Method,
			Path:             req.Path,
			GraphQLOperation: req.GraphQLOperation,
			GRPCService:      req.GRPCService,
			GRPCMethod:       req.GRPCMethod,
			Principal:        principal,
			Headers:          req.Headers,
		}
		decision, err = e.Policy.Evaluate(ctx, input)
		policySpan.End()
		if err != nil {
			return &Response{
				Allow:      false,
				StatusCode: http.StatusInternalServerError,
				Body:       []byte(`{"errors":[{"message":"policy error"}]}`),
			}, nil
		}
	}

	if decision == nil {
		decision = &policy.Decision{Allow: false, StatusCode: http.StatusServiceUnavailable}
	}

	_, upstreamSpan := tr.StartSpan(ctx, "proxy.upstream_build")
	resp := &Response{
		Allow:      decision.Allow,
		StatusCode: decision.StatusCode,
		Body:       nil,
	}
	if decision.Reason != "" && !decision.Allow {
		resp.Body = []byte(`{"errors":[{"message":"` + escapeJSON(decision.Reason) + `"}]}`)
	}
	if decision.Headers != nil {
		resp.UpstreamHeaders = make(map[string]string)
		for k, v := range decision.Headers {
			resp.UpstreamHeaders[k] = v
		}
	}
	// Merge obligations into headers (e.g. "set_header_X_User" -> "X-User")
	if decision.Obligations != nil {
		if resp.UpstreamHeaders == nil {
			resp.UpstreamHeaders = make(map[string]string)
		}
		for k, v := range decision.Obligations {
			if s, ok := v.(string); ok && strings.HasPrefix(k, "set_header_") {
				headerName := strings.TrimPrefix(k, "set_header_")
				headerName = strings.ReplaceAll(headerName, "_", "-")
				// Strip CRLF to prevent header injection.
				headerName = strings.Map(func(r rune) rune {
					if r == '\r' || r == '\n' {
						return -1
					}
					return r
				}, headerName)
				s = strings.Map(func(r rune) rune {
					if r == '\r' || r == '\n' {
						return -1
					}
					return r
				}, s)
				resp.UpstreamHeaders[headerName] = s
			}
		}
	}
	// Build headers from principal when allowed
	if decision.Allow && principal != nil {
		hb := e.HeaderBuilder
		if hb == nil {
			hb = defaultHeaderBuilder
		}
		built := hb(principal, decision.Obligations)
		if resp.UpstreamHeaders == nil {
			resp.UpstreamHeaders = built
		} else {
			for k, v := range built {
				resp.UpstreamHeaders[k] = v
			}
		}
	}
	if e.Metrics != nil {
		e.Metrics.AuthDecision(resp.Allow, resp.StatusCode)
	}
	upstreamSpan.End()
	return resp, nil
}

func defaultHeaderBuilder(principal *token.Principal, obligations map[string]any) map[string]string {
	if principal == nil {
		return map[string]string{}
	}
	h := make(map[string]string)
	if principal.AccessToken != "" {
		h["Authorization"] = "Bearer " + principal.AccessToken
	}
	if principal.Subject != "" {
		h["X-User-Id"] = principal.Subject
	}
	if len(principal.Roles) > 0 {
		h["X-Roles"] = strings.Join(principal.Roles, ",")
	}
	if principal.Claims != nil {
		if v, ok := principal.Claims["email"].(string); ok && v != "" {
			h["X-User-Email"] = v
		}
		if v, ok := principal.Claims["name"].(string); ok && v != "" {
			h["X-User-Full-Name"] = v
		}
		if v, ok := principal.Claims["preferred_username"].(string); ok && v != "" {
			h["X-User-Preferred-Username"] = v
		}
	}
	if principal.TenantContext != nil {
		if v, ok := principal.TenantContext["tenant_id"].(string); ok && v != "" {
			h["X-Tenant-Id"] = v
		}
	}
	return h
}

func escapeJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	// json.Marshal wraps the string in quotes; strip them.
	return string(b[1 : len(b)-1])
}
