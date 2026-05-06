package main

import (
	"context"

	pkgproxy "github.com/ArmanAvanesyan/accessgate/internal/authz"
	"github.com/ArmanAvanesyan/accessgate/internal/policy"
	"github.com/ArmanAvanesyan/accessgate/pkg/token"
)

type policyEngineAdapter struct {
	engine policy.Engine
	status policy.EngineWithStatus
}

func adaptPolicyEngine(engine policy.Engine) pkgproxy.PolicyEngine {
	if engine == nil {
		return nil
	}
	adapter := &policyEngineAdapter{engine: engine}
	if status, ok := engine.(policy.EngineWithStatus); ok {
		adapter.status = status
	}
	return adapter
}

func (a *policyEngineAdapter) Evaluate(ctx context.Context, input pkgproxy.PolicyInput) (*pkgproxy.PolicyDecision, error) {
	decision, err := a.engine.Evaluate(ctx, policy.Input{
		Protocol:         input.Protocol,
		Method:           input.Method,
		Path:             input.Path,
		GraphQLOperation: input.GraphQLOperation,
		GRPCService:      input.GRPCService,
		GRPCMethod:       input.GRPCMethod,
		Principal:        principalToToken(input.Principal),
		Headers:          input.Headers,
	})
	if err != nil || decision == nil {
		return nil, err
	}
	return &pkgproxy.PolicyDecision{
		Allow:       decision.Allow,
		StatusCode:  decision.StatusCode,
		Headers:     decision.Headers,
		Reason:      decision.Reason,
		Obligations: decision.Obligations,
	}, nil
}

func (a *policyEngineAdapter) Loaded() bool {
	return a.status != nil && a.status.Loaded()
}

func (a *policyEngineAdapter) BundlePath() string {
	if a.status == nil {
		return ""
	}
	return a.status.BundlePath()
}

func principalToToken(principal *pkgproxy.Principal) *token.Principal {
	if principal == nil {
		return nil
	}
	return &token.Principal{
		Subject:       principal.Subject,
		Roles:         principal.Roles,
		Claims:        principal.Claims,
		ExpiresAt:     principal.ExpiresAt,
		AccessToken:   principal.AccessToken,
		TenantContext: principal.TenantContext,
	}
}
