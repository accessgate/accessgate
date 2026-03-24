package plugin

import (
	"context"
	"testing"
	"time"
)

type stubHost struct{}

func (stubHost) Logger() Logger   { return nil }
func (stubHost) Metrics() Metrics { return nil }
func (stubHost) Cache() Cache     { return nil }
func (stubHost) Secrets() Secrets { return nil }
func (stubHost) Clock() Clock     { return stubClock{} }

type stubClock struct{}

func (stubClock) Now() time.Time { return time.Unix(0, 0) }

var _ HostServices = stubHost{}

func TestStubHostImplementsHostServices(t *testing.T) {
	var h HostServices = stubHost{}
	_ = h.Clock().Now()
}

type stubCache struct{}

func (stubCache) Get(ctx context.Context, key string) (string, error) { return "", nil }
func (stubCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return nil
}
func (stubCache) Del(ctx context.Context, key string) error { return nil }

var _ Cache = stubCache{}
