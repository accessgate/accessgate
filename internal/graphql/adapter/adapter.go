// Package adapter normalizes HTTP GraphQL requests into authz.Request values.
//
// It lives in a sub-package (rather than in package graphql) so that the
// dependency-free parser in package graphql can be imported by internal/authz
// for operation-name extraction without creating an import cycle.
package adapter

import (
	"net/http"

	"github.com/accessgate/accessgate/internal/authz"
	"github.com/accessgate/accessgate/internal/graphql"
)

// NormalizeHTTPRequest converts an HTTP GraphQL request into an authz.Request.
//
// It reuses authz.RequestFromHTTP for the shared HTTP-to-Request normalization
// (header/cookie/body extraction, SSRF-safe body limits, and the existing
// header/JSON GraphQL operation-name detection), then ensures GraphQL fields
// are populated by parsing the body — including raw GraphQL documents that the
// authz normalizer alone would not recognize.
func NormalizeHTTPRequest(r *http.Request) (*authz.Request, error) {
	req, err := authz.RequestFromHTTP(r)
	if err != nil {
		return nil, err
	}
	name, opType := graphql.ExtractOperation(req.Body)
	if req.GraphQLOperation == "" {
		req.GraphQLOperation = name
	}
	if req.GraphQLOperationType == "" {
		req.GraphQLOperationType = opType
	}
	return req, nil
}
