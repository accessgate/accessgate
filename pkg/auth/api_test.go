package auth

import "context"

// Compile-time check: Service is implemented by a concrete type in production.
var _ Service = (*noopService)(nil)

type noopService struct{}

func (noopService) Session(ctx context.Context, req SessionRequest) (*SessionResponse, error) {
	return &SessionResponse{}, nil
}

func (noopService) LoginStart(ctx context.Context, req LoginStartRequest) (*LoginStartResponse, error) {
	return &LoginStartResponse{}, nil
}

func (noopService) LoginEnd(ctx context.Context, req LoginEndRequest) (*LoginEndResponse, error) {
	return &LoginEndResponse{}, nil
}

func (noopService) Refresh(ctx context.Context, req RefreshRequest) (*RefreshResponse, error) {
	return &RefreshResponse{}, nil
}

func (noopService) Logout(ctx context.Context, req LogoutRequest) (*LogoutResponse, error) {
	return &LogoutResponse{}, nil
}
