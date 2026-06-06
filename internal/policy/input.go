package policy

import "github.com/accessgate/accessgate/pkg/token"

// Input is the normalized authorization input passed to the policy engine.
type Input struct {
	Protocol         string
	Method           string
	Path             string
	GraphQLOperation string
	GRPCService      string
	GRPCMethod       string
	Principal        *token.Principal
	Headers          map[string]string
}
