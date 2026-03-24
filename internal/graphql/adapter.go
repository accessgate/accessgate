package graphql

import (
	"fmt"
	"net/http"

	"github.com/ArmanAvanesyan/accessgate/internal/authz"
)

// NormalizeHTTPRequest converts an HTTP GraphQL request into a authz.Request.
// Not yet implemented — returns an error so callers cannot silently bypass authorization.
func NormalizeHTTPRequest(_ *http.Request) (*authz.Request, error) {
	return nil, fmt.Errorf("graphql: NormalizeHTTPRequest not implemented")
}
