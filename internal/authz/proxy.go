package authz

import "context"

// Engine is the core OAuth proxy engine.
type Engine interface {
	Handle(ctx context.Context, req *Request) (*Response, error)
}
