package auth

import "context"

// Service is the OAuth Agent runtime interface.
type Service interface {
	Session(ctx context.Context, req SessionRequest) (*SessionResponse, error)
	LoginStart(ctx context.Context, req LoginStartRequest) (*LoginStartResponse, error)
	LoginEnd(ctx context.Context, req LoginEndRequest) (*LoginEndResponse, error)
	Refresh(ctx context.Context, req RefreshRequest) (*RefreshResponse, error)
	Logout(ctx context.Context, req LogoutRequest) (*LogoutResponse, error)
}
