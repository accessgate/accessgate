package graphql

// GraphQLRequest holds parsed GraphQL request details for policy input.
type GraphQLRequest struct {
	// OperationName is the name of the GraphQL operation, or "" for anonymous
	// operations.
	OperationName string
	// OperationType is "query", "mutation", or "subscription". It is "" when
	// the body could not be parsed as a GraphQL document.
	OperationType string
}

// ParseRequest parses a GraphQL request body into a GraphQLRequest.
func ParseRequest(body []byte) GraphQLRequest {
	name, opType := ExtractOperation(body)
	return GraphQLRequest{OperationName: name, OperationType: opType}
}
